"""Phase 6-6  –  End-to-end inference: ATT&CK Technique → NIST 800-53 Controls.

Usage:
    python Phase6-6_run_pipeline.py --techniques_file data/input_techniques.txt

Input:  A .txt file containing comma-separated ATT&CK technique / sub-technique
        IDs (e.g.  T1190,T1059.001,T1530).  This matches the output format of
        the upstream CVE → ATT&CK model.
Output: JSON with ranked controls + confidence + justification per technique.

Strategy:
    * Known technique  → return all known mappings (source=known_mapping)
                         PLUS any high-confidence classifier predictions not
                         already in the known set (source=predicted_extra).
    * Unknown technique → classifier predictions only (source=predicted).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoModel, AutoTokenizer

ROOT     = Path(__file__).resolve().parent.parent.parent
DATA     = Path(__file__).resolve().parent / "data"
MODELS   = Path(__file__).resolve().parent / "models"
RESULTS  = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)

DEVICE   = torch.device("cuda" if torch.cuda.is_available() else "cpu")
MAX_LEN  = 128
MODEL_NAME = "ehsanaghaei/SecureBERT"
EXTRA_THRESHOLD = 0.5


# ---------------------------------------------------------------------------
# Classifier head (mirrored from Phase 6-3)
# ---------------------------------------------------------------------------

class ControlClassifier(nn.Module):
    def __init__(self, input_dim, hidden_dim, n_controls):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, n_controls),
        )
    def forward(self, x):
        return self.net(x)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class ATTACKtoNISTPipeline:
    def __init__(self):
        # Embeddings
        emb = torch.load(DATA / "embeddings.pt", map_location="cpu")
        self.tech_ids: list[str] = emb["technique_ids"]
        self.ctrl_ids: list[str] = emb["control_ids"]
        self.tech_embs: torch.Tensor = emb["technique_embeddings"]
        self.ctrl_embs: torch.Tensor = emb["control_embeddings"]
        self.tech_id_to_idx = {t: i for i, t in enumerate(self.tech_ids)}

        # Classifier
        ckpt = torch.load(MODELS / "classifier_best.pt", map_location="cpu")
        self.classifier = ControlClassifier(ckpt["input_dim"], ckpt["hidden_dim"], ckpt["n_controls"])
        self.classifier.load_state_dict(ckpt["state_dict"])
        self.classifier.eval()
        self.clf_ctrl_ids: list[str] = ckpt["ctrl_ids"]
        self.clf_ctrl_to_idx = {c: i for i, c in enumerate(self.clf_ctrl_ids)}

        # Known mappings
        with open(DATA / "known_mappings.json") as f:
            self.known: dict[str, list[str]] = json.load(f)
        with open(DATA / "known_comments.json") as f:
            self.known_comments: dict[str, dict[str, str]] = json.load(f)

        # Technique texts (for ad-hoc encoding of unknown techniques)
        with open(DATA / "technique_texts.json") as f:
            self.tech_texts: dict[str, str] = json.load(f)

        # Encoder for unknown techniques
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        self.encoder = AutoModel.from_pretrained(MODEL_NAME).to(DEVICE).eval()

    def _encode_text(self, text: str) -> torch.Tensor:
        enc = self.tokenizer([text], padding=True, truncation=True,
                             max_length=MAX_LEN, return_tensors="pt").to(DEVICE)
        with torch.no_grad():
            out = self.encoder(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"])
            mask = enc["attention_mask"].unsqueeze(-1).expand(out.last_hidden_state.size()).float()
            pooled = (out.last_hidden_state * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
        return F.normalize(pooled, dim=-1).cpu().squeeze(0)

    def _get_embedding(self, tid: str) -> torch.Tensor:
        idx = self.tech_id_to_idx.get(tid)
        if idx is not None:
            return self.tech_embs[idx]
        text = self.tech_texts.get(tid, tid)
        return self._encode_text(text)

    def _classifier_probs(self, emb: torch.Tensor) -> dict[str, float]:
        with torch.no_grad():
            probs = self.classifier(emb.unsqueeze(0)).sigmoid().squeeze(0).numpy()
        return {self.clf_ctrl_ids[i]: float(probs[i]) for i in range(len(self.clf_ctrl_ids))}

    def predict(self, technique_ids: list[str], extra_threshold: float = EXTRA_THRESHOLD) -> list[dict]:
        results: list[dict] = []

        for tid in technique_ids:
            emb = self._get_embedding(tid)
            clf_probs = self._classifier_probs(emb)
            known_ctrls = set(self.known.get(tid, []))
            is_known = len(known_ctrls) > 0

            controls: list[dict] = []

            # Known mappings (score = 1.0)
            for cid in sorted(known_ctrls):
                comment = self.known_comments.get(tid, {}).get(cid, "")
                controls.append({
                    "control_id": cid,
                    "score": 1.0,
                    "classifier_prob": round(clf_probs.get(cid, 0.0), 4),
                    "source": "known_mapping",
                    "justification": comment if comment else "Known ATT&CK-to-NIST mapping.",
                })

            # Classifier predictions
            for cid, prob in sorted(clf_probs.items(), key=lambda x: -x[1]):
                if cid in known_ctrls:
                    continue
                if is_known and prob < extra_threshold:
                    continue
                if not is_known and prob < 0.3:
                    continue

                similar = self._find_similar_known(tid, cid)
                source = "predicted_extra" if is_known else "predicted"
                controls.append({
                    "control_id": cid,
                    "score": round(prob, 4),
                    "classifier_prob": round(prob, 4),
                    "source": source,
                    "justification": self._format_justification(similar, prob),
                })

            controls.sort(key=lambda x: -x["score"])

            tech_name = self.tech_texts.get(tid, "").split("|")[0].strip()
            results.append({
                "technique_id": tid,
                "technique_name": tech_name,
                "known_controls": len(known_ctrls),
                "predicted_extra": sum(1 for c in controls if c["source"] in ("predicted_extra", "predicted")),
                "controls": controls,
            })

        return results

    def _find_similar_known(self, tid: str, cid: str, top_k: int = 3) -> list[dict]:
        tidx = self.tech_id_to_idx.get(tid)
        if tidx is None:
            return []
        similar: list[dict] = []
        for kt, kt_ctrls in self.known.items():
            if cid not in kt_ctrls:
                continue
            kidx = self.tech_id_to_idx.get(kt)
            if kidx is None:
                continue
            sim = float(self.tech_embs[tidx] @ self.tech_embs[kidx])
            comment = self.known_comments.get(kt, {}).get(cid, "")
            similar.append({"technique": kt, "similarity": round(sim, 4), "comment": comment})
        similar.sort(key=lambda x: -x["similarity"])
        return similar[:top_k]

    @staticmethod
    def _format_justification(similar: list[dict], prob: float) -> str:
        parts = [f"Classifier confidence: {prob:.1%}."]
        if similar:
            refs = ", ".join(f"{s['technique']} (sim={s['similarity']:.2f})" for s in similar)
            parts.append(f"Similar known mappings: {refs}.")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="ATT&CK → NIST 800-53 inference")
    parser.add_argument("--techniques_file", type=str, required=True,
                        help="Path to .txt file with comma-separated technique IDs")
    parser.add_argument("--extra_threshold", type=float, default=EXTRA_THRESHOLD,
                        help="Min classifier probability for extra predictions on known techniques")
    parser.add_argument("--output", type=str, default=str(RESULTS / "pipeline_output.json"))
    args = parser.parse_args()

    raw = Path(args.techniques_file).read_text().strip()
    technique_ids = [t.strip() for t in raw.split(",") if t.strip()]
    print(f"Loaded {len(technique_ids)} techniques from {args.techniques_file}")

    print("Loading pipeline …")
    pipeline = ATTACKtoNISTPipeline()

    print(f"Running inference …")
    results = pipeline.predict(technique_ids, extra_threshold=args.extra_threshold)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nOutput saved to {args.output}")

    for r in results:
        print(f"\n{'='*70}")
        print(f"{r['technique_id']}  {r['technique_name'][:60]}")

        known = [c for c in r["controls"] if c["source"] == "known_mapping"]
        predicted = [c for c in r["controls"] if c["source"] in ("predicted_extra", "predicted")]

        if known:
            print(f"\n  KNOWN MAPPINGS ({len(known)} controls):")
            for c in known:
                print(f"    {c['control_id']:12s}  classifier_prob={c['classifier_prob']:.2%}")
        else:
            print(f"\n  KNOWN MAPPINGS: none (technique not in known mapping database)")

        if predicted:
            label = "PREDICTED EXTRA" if known else "PREDICTED"
            print(f"\n  {label} ({len(predicted)} controls, ranked by classifier probability):")
            for c in predicted[:10]:
                print(f"    {c['control_id']:12s}  classifier_prob={c['classifier_prob']:.2%}")
            if len(predicted) > 10:
                print(f"    … and {len(predicted) - 10} more (see JSON output)")
        else:
            print(f"\n  PREDICTED EXTRA: none above threshold")


if __name__ == "__main__":
    main()
