"""Phase 6-3  –  Multi-label classifier on frozen SecureBERT embeddings.

Trains on ALL 470 known-mapped techniques (no hold-out split — the known
mappings serve as a direct lookup at inference, so the classifier only needs
to generalise to unseen techniques).

A small leave-one-out evaluation is done at the end to measure how well
the classifier fills gaps for techniques it has never seen.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

DATA   = Path(__file__).resolve().parent / "data"
MODELS = Path(__file__).resolve().parent / "models"
MODELS.mkdir(exist_ok=True)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

EPOCHS     = 150
LR         = 1e-3
BATCH_SIZE = 64
HIDDEN     = 256


# ---------------------------------------------------------------------------
# Classifier head
# ---------------------------------------------------------------------------

class ControlClassifier(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int, n_controls: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, n_controls),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


# ---------------------------------------------------------------------------
# Training (all data)
# ---------------------------------------------------------------------------

def train() -> None:
    emb_data = torch.load(DATA / "embeddings.pt", map_location="cpu")
    tech_ids: list[str] = emb_data["technique_ids"]
    tech_embs: torch.Tensor = emb_data["technique_embeddings"]
    tech_id_to_idx = {t: i for i, t in enumerate(tech_ids)}

    with open(DATA / "classifier_labels.json") as f:
        labels_dict: dict[str, list[int]] = json.load(f)
    with open(DATA / "all_control_ids.json") as f:
        ctrl_ids: list[str] = json.load(f)

    n_ctrl = len(ctrl_ids)
    input_dim = tech_embs.shape[1]

    labelled_tids = sorted(t for t in labels_dict if t in tech_id_to_idx)
    emb_rows = [tech_id_to_idx[t] for t in labelled_tids]
    X = tech_embs[emb_rows]
    Y = torch.tensor([labels_dict[t] for t in labelled_tids], dtype=torch.float32)

    print(f"Training on ALL {X.shape[0]} techniques × {n_ctrl} controls")
    print(f"  Positive labels: {int(Y.sum().item())}, avg per technique: {Y.sum().item()/X.shape[0]:.1f}")

    pos_counts = Y.sum(0).clamp(min=1)
    neg_counts = Y.shape[0] - pos_counts
    pos_weight = (neg_counts / pos_counts).to(DEVICE)

    model = ControlClassifier(input_dim, HIDDEN, n_ctrl).to(DEVICE)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    ds = TensorDataset(X, Y)
    loader = DataLoader(ds, batch_size=BATCH_SIZE, shuffle=True)

    for epoch in range(1, EPOCHS + 1):
        model.train()
        total_loss = 0.0
        for xb, yb in loader:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            logits = model(xb)
            loss = criterion(logits, yb)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * xb.size(0)

        if epoch % 25 == 0 or epoch == 1:
            avg_loss = total_loss / len(ds)
            model.eval()
            with torch.no_grad():
                all_logits = model(X.to(DEVICE))
                preds = (all_logits.sigmoid() > 0.5).float().cpu()
            tp = (preds * Y).sum().item()
            fp = (preds * (1 - Y)).sum().item()
            fn = ((1 - preds) * Y).sum().item()
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
            print(f"Epoch {epoch:3d}  loss={avg_loss:.4f}  train_P={prec:.3f} R={rec:.3f} F1={f1:.3f}", flush=True)

    torch.save({
        "state_dict": model.state_dict(),
        "ctrl_ids": ctrl_ids,
        "input_dim": input_dim,
        "hidden_dim": HIDDEN,
        "n_controls": n_ctrl,
    }, MODELS / "classifier_best.pt")
    print(f"Saved model to {MODELS / 'classifier_best.pt'}")

    # --- Leave-one-out evaluation ---
    print("\nLeave-one-out evaluation (classifier generalisation) …")
    _leave_one_out_eval(X, Y, labelled_tids, input_dim, n_ctrl, pos_weight)


def _leave_one_out_eval(X, Y, tids, input_dim, n_ctrl, pos_weight, n_folds=10):
    """Quick k-fold (not full LOO) to estimate generalisation."""
    indices = np.arange(len(tids))
    np.random.seed(42)
    np.random.shuffle(indices)
    fold_size = len(indices) // n_folds

    all_mrrs: list[float] = []
    all_p5: list[float] = []

    for fold in range(n_folds):
        test_idx = indices[fold * fold_size:(fold + 1) * fold_size]
        train_idx = np.concatenate([indices[:fold * fold_size], indices[(fold + 1) * fold_size:]])

        tr_X, tr_Y = X[train_idx], Y[train_idx]
        te_X, te_Y = X[test_idx], Y[test_idx]

        model = ControlClassifier(input_dim, HIDDEN, n_ctrl).to(DEVICE)
        optimizer = torch.optim.Adam(model.parameters(), lr=LR)
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

        ds = TensorDataset(tr_X, tr_Y)
        loader = DataLoader(ds, batch_size=BATCH_SIZE, shuffle=True)
        for _ in range(100):
            model.train()
            for xb, yb in loader:
                xb, yb = xb.to(DEVICE), yb.to(DEVICE)
                loss = criterion(model(xb), yb)
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()

        model.eval()
        with torch.no_grad():
            probs = model(te_X.to(DEVICE)).sigmoid().cpu().numpy()

        for i in range(len(test_idx)):
            gold = set(np.where(te_Y[i].numpy() == 1)[0])
            ranked = np.argsort(-probs[i])
            for rank, idx in enumerate(ranked[:10], 1):
                if idx in gold:
                    all_mrrs.append(1.0 / rank)
                    break
            else:
                all_mrrs.append(0.0)
            hits = sum(1 for idx in ranked[:5] if idx in gold)
            all_p5.append(hits / 5)

    print(f"  {n_folds}-fold CV:  MRR@10={np.mean(all_mrrs):.4f}  P@5={np.mean(all_p5):.4f}")


if __name__ == "__main__":
    train()
