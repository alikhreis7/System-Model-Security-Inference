"""Phase 6-2  –  Bi-Encoder fine-tuning (SecureBERT + InfoNCE / MNRL).

Trains a Siamese-style bi-encoder that produces 768-dim embeddings for both
ATT&CK techniques and NIST 800-53 controls.  At inference the cosine
similarity between a technique vector and every control vector is used as a
relevance score.

Model backbone: ehsanaghaei/SecureBERT
Loss:           MultipleNegativesRankingLoss (in-batch negatives)
Metric:         MRR@10 on the validation set
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModel, AutoTokenizer, get_linear_schedule_with_warmup

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

DATA   = Path(__file__).resolve().parent / "data"
MODELS = Path(__file__).resolve().parent / "models"
MODELS.mkdir(exist_ok=True)

MODEL_NAME = "ehsanaghaei/SecureBERT"
MAX_LEN    = 128
BATCH_SIZE = 16
EPOCHS     = 5
LR         = 2e-5
WARMUP_RATIO = 0.1
EMBED_DIM  = 768


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

class PairDataset(Dataset):
    """Yields (technique_text, positive_control_text) pairs for MNRL."""

    def __init__(self, pairs_file: str, tech_texts: dict, ctrl_texts: dict):
        with open(pairs_file) as f:
            raw = json.load(f)
        self.pairs = [p for p in raw if p["label"] == 1]
        self.tech_texts = tech_texts
        self.ctrl_texts = ctrl_texts

    def __len__(self) -> int:
        return len(self.pairs)

    def __getitem__(self, idx: int) -> tuple[str, str]:
        p = self.pairs[idx]
        t_text = self.tech_texts.get(p["technique_id"], p["technique_id"])
        c_text = self.ctrl_texts.get(p["control_id"], p["control_id"])
        return t_text, c_text


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class BiEncoder(nn.Module):
    def __init__(self, model_name: str = MODEL_NAME):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(model_name)

    def _mean_pool(self, last_hidden: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        expanded = mask.unsqueeze(-1).expand(last_hidden.size()).float()
        return (last_hidden * expanded).sum(1) / expanded.sum(1).clamp(min=1e-9)

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        out = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        return F.normalize(self._mean_pool(out.last_hidden_state, attention_mask), dim=-1)


# ---------------------------------------------------------------------------
# MNRL loss  (in-batch negatives)
# ---------------------------------------------------------------------------

def mnrl_loss(q_emb: torch.Tensor, p_emb: torch.Tensor, temperature: float = 0.05) -> torch.Tensor:
    """Multiple Negatives Ranking Loss (InfoNCE with in-batch negatives)."""
    scores = q_emb @ p_emb.T / temperature  # (B, B)
    labels = torch.arange(scores.size(0), device=scores.device)
    return F.cross_entropy(scores, labels)


# ---------------------------------------------------------------------------
# Evaluation  –  MRR@10
# ---------------------------------------------------------------------------

@torch.no_grad()
def compute_mrr(model: BiEncoder, tokenizer, tech_texts: dict, ctrl_texts: dict,
                pairs_file: str, k: int = 10) -> float:
    model.eval()

    with open(pairs_file) as f:
        pairs = [p for p in json.load(f) if p["label"] == 1]

    from collections import defaultdict
    tech_to_controls: dict[str, set[str]] = defaultdict(set)
    for p in pairs:
        tech_to_controls[p["technique_id"]].add(p["control_id"])

    ctrl_ids = sorted(ctrl_texts.keys())
    ctrl_txts = [ctrl_texts[c] for c in ctrl_ids]

    ctrl_embs = _batch_encode(model, tokenizer, ctrl_txts)

    rrs: list[float] = []
    tech_ids = sorted(tech_to_controls.keys())
    tech_txts = [tech_texts.get(t, t) for t in tech_ids]
    tech_embs = _batch_encode(model, tokenizer, tech_txts)

    for i, tid in enumerate(tech_ids):
        scores = tech_embs[i] @ ctrl_embs.T
        topk_idx = scores.topk(k).indices.tolist()
        gold = tech_to_controls[tid]
        for rank, idx in enumerate(topk_idx, 1):
            if ctrl_ids[idx] in gold:
                rrs.append(1.0 / rank)
                break
        else:
            rrs.append(0.0)

    return float(np.mean(rrs))


def _batch_encode(model: BiEncoder, tokenizer, texts: list[str],
                  batch_size: int = 64) -> torch.Tensor:
    all_embs = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        enc = tokenizer(batch, padding=True, truncation=True,
                        max_length=MAX_LEN, return_tensors="pt").to(DEVICE)
        emb = model(enc["input_ids"], enc["attention_mask"])
        all_embs.append(emb.cpu())
    return torch.cat(all_embs, dim=0)


# ---------------------------------------------------------------------------
# Training loop
# ---------------------------------------------------------------------------

def collate_fn(batch, tokenizer):
    techs, ctrls = zip(*batch)
    t_enc = tokenizer(list(techs), padding=True, truncation=True,
                      max_length=MAX_LEN, return_tensors="pt")
    c_enc = tokenizer(list(ctrls), padding=True, truncation=True,
                      max_length=MAX_LEN, return_tensors="pt")
    return t_enc, c_enc


def train() -> None:
    print(f"Device: {DEVICE}")

    with open(DATA / "technique_texts.json") as f:
        tech_texts = json.load(f)
    with open(DATA / "control_texts.json") as f:
        ctrl_texts = json.load(f)

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = BiEncoder(MODEL_NAME).to(DEVICE)

    train_ds = PairDataset(str(DATA / "train_pairs.json"), tech_texts, ctrl_texts)
    print(f"Training pairs (positive): {len(train_ds)}")
    loader = DataLoader(
        train_ds,
        batch_size=BATCH_SIZE,
        shuffle=True,
        collate_fn=lambda b: collate_fn(b, tokenizer),
        num_workers=0,
    )
    print(f"Batches per epoch: {len(loader)}")

    optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=0.01)
    total_steps = len(loader) * EPOCHS
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(total_steps * WARMUP_RATIO),
        num_training_steps=total_steps,
    )

    best_mrr = 0.0
    for epoch in range(1, EPOCHS + 1):
        model.train()
        total_loss = 0.0
        for step, (t_enc, c_enc) in enumerate(loader, 1):
            t_enc = {k: v.to(DEVICE) for k, v in t_enc.items()}
            c_enc = {k: v.to(DEVICE) for k, v in c_enc.items()}

            q = model(t_enc["input_ids"], t_enc["attention_mask"])
            p = model(c_enc["input_ids"], c_enc["attention_mask"])
            loss = mnrl_loss(q, p)

            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()

            total_loss += loss.item()
            if step % 10 == 0 or step == 1:
                print(f"  epoch {epoch}  step {step}/{len(loader)}  loss={loss.item():.4f}", flush=True)

        avg_loss = total_loss / len(loader)
        val_mrr = compute_mrr(model, tokenizer, tech_texts, ctrl_texts,
                              str(DATA / "val_pairs.json"))
        print(f"Epoch {epoch}  avg_loss={avg_loss:.4f}  val_MRR@10={val_mrr:.4f}")

        if val_mrr > best_mrr:
            best_mrr = val_mrr
            torch.save(model.state_dict(), MODELS / "biencoder_best.pt")
            tokenizer.save_pretrained(str(MODELS / "biencoder_tokenizer"))
            print(f"  -> saved best model (MRR@10={best_mrr:.4f})")

    print(f"\nTraining complete. Best val MRR@10 = {best_mrr:.4f}")


# ---------------------------------------------------------------------------
# Embedding export  (used by Phase 6-3 classifier)
# ---------------------------------------------------------------------------

def export_embeddings() -> None:
    """Encode all techniques and controls with the best checkpoint."""
    with open(DATA / "technique_texts.json") as f:
        tech_texts = json.load(f)
    with open(DATA / "control_texts.json") as f:
        ctrl_texts = json.load(f)

    tokenizer = AutoTokenizer.from_pretrained(str(MODELS / "biencoder_tokenizer"))
    model = BiEncoder(MODEL_NAME).to(DEVICE)
    model.load_state_dict(torch.load(MODELS / "biencoder_best.pt", map_location=DEVICE))
    model.eval()

    tech_ids = sorted(tech_texts.keys())
    ctrl_ids = sorted(ctrl_texts.keys())
    tech_embs = _batch_encode(model, tokenizer, [tech_texts[t] for t in tech_ids])
    ctrl_embs = _batch_encode(model, tokenizer, [ctrl_texts[c] for c in ctrl_ids])

    torch.save({
        "technique_ids": tech_ids,
        "control_ids": ctrl_ids,
        "technique_embeddings": tech_embs,
        "control_embeddings": ctrl_embs,
    }, DATA / "embeddings.pt")
    print(f"Exported embeddings: {len(tech_ids)} techniques, {len(ctrl_ids)} controls")


if __name__ == "__main__":
    train()
    export_embeddings()
