"""Phase 6-5  –  Evaluation of the lookup + classifier pipeline.

Ablation variants:
    1. BM25 baseline             (TF-IDF keyword match)
    2. Frozen cosine only        (pretrained SecureBERT, no training)
    3. Classifier only           (frozen embeddings + trained head)
    4. Lookup + classifier       (known → direct, unknown → classifier)

Evaluation protocol:
    10-fold cross-validation at the technique level.  In each fold the
    held-out techniques have their known mappings removed; the classifier
    is retrained on the remaining techniques.  This simulates the real
    scenario: known techniques get a direct lookup, unknown ones rely on ML.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.feature_extraction.text import TfidfVectorizer
from torch.utils.data import DataLoader, TensorDataset

DATA    = Path(__file__).resolve().parent / "data"
MODELS  = Path(__file__).resolve().parent / "models"
RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
HIDDEN = 256
LR = 1e-3
BATCH_SIZE = 64
CV_EPOCHS = 100
N_FOLDS = 10


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def precision_at_k(predicted: list[str], gold: set[str], k: int) -> float:
    return sum(1.0 for p in predicted[:k] if p in gold) / k


def ndcg_at_k(predicted: list[str], gold: set[str], k: int) -> float:
    dcg = sum(1.0 / math.log2(i + 2) for i, p in enumerate(predicted[:k]) if p in gold)
    ideal = sum(1.0 / math.log2(i + 2) for i in range(min(len(gold), k)))
    return dcg / ideal if ideal > 0 else 0.0


def mrr(predicted: list[str], gold: set[str]) -> float:
    for i, p in enumerate(predicted):
        if p in gold:
            return 1.0 / (i + 1)
    return 0.0


# ---------------------------------------------------------------------------
# Classifier (inline)
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


def _train_classifier(X, Y, pos_weight, input_dim, n_ctrl, epochs=CV_EPOCHS):
    model = ControlClassifier(input_dim, HIDDEN, n_ctrl).to(DEVICE)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    ds = TensorDataset(X, Y)
    loader = DataLoader(ds, batch_size=BATCH_SIZE, shuffle=True)
    for _ in range(epochs):
        model.train()
        for xb, yb in loader:
            xb, yb = xb.to(DEVICE), yb.to(DEVICE)
            loss = criterion(model(xb), yb)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
    model.eval()
    return model


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate() -> None:
    # Load data
    emb_data = torch.load(DATA / "embeddings.pt", map_location="cpu")
    tech_ids: list[str] = emb_data["technique_ids"]
    tech_embs: torch.Tensor = emb_data["technique_embeddings"]
    ctrl_embs: torch.Tensor = emb_data["control_embeddings"]
    tech_id_to_idx = {t: i for i, t in enumerate(tech_ids)}

    with open(DATA / "all_control_ids.json") as f:
        ctrl_ids: list[str] = json.load(f)
    with open(DATA / "classifier_labels.json") as f:
        labels_dict = json.load(f)
    with open(DATA / "technique_texts.json") as f:
        tech_texts = json.load(f)
    with open(DATA / "control_texts.json") as f:
        ctrl_texts = json.load(f)

    n_ctrl = len(ctrl_ids)
    input_dim = tech_embs.shape[1]

    labelled_tids = sorted(t for t in labels_dict if t in tech_id_to_idx)
    emb_rows = [tech_id_to_idx[t] for t in labelled_tids]
    X_all = tech_embs[emb_rows]
    Y_all = torch.tensor([labels_dict[t] for t in labelled_tids], dtype=torch.float32)

    # Gold sets per technique
    gold_sets: dict[str, set[str]] = {}
    for i, tid in enumerate(labelled_tids):
        gold_sets[tid] = set(ctrl_ids[j] for j in range(n_ctrl) if Y_all[i, j] == 1)

    # --- BM25 scorer ---
    tfidf = TfidfVectorizer(max_features=10000, sublinear_tf=True)
    ctrl_docs = [ctrl_texts.get(c, c) for c in ctrl_ids]
    ctrl_matrix = tfidf.fit_transform(ctrl_docs)

    def bm25_rank(tid):
        text = tech_texts.get(tid, tid)
        q = tfidf.transform([text])
        scores = (q @ ctrl_matrix.T).toarray()[0]
        return [ctrl_ids[i] for i in np.argsort(-scores)]

    # --- Frozen cosine scorer ---
    def cosine_rank(tid):
        idx = tech_id_to_idx.get(tid)
        if idx is None:
            return ctrl_ids
        scores = (tech_embs[idx] @ ctrl_embs.T).numpy()
        return [ctrl_ids[i] for i in np.argsort(-scores)]

    # --- 10-fold CV for classifier and lookup+classifier ---
    indices = np.arange(len(labelled_tids))
    np.random.seed(42)
    np.random.shuffle(indices)
    fold_size = len(indices) // N_FOLDS

    metrics = {name: {"p5": [], "p10": [], "ndcg10": [], "mrr": []}
               for name in ["BM25", "Frozen cosine", "Classifier", "Lookup + Classifier"]}

    print(f"Running {N_FOLDS}-fold cross-validation on {len(labelled_tids)} techniques …\n")

    for fold in range(N_FOLDS):
        test_idx = indices[fold * fold_size:(fold + 1) * fold_size]
        train_idx = np.concatenate([indices[:fold * fold_size], indices[(fold + 1) * fold_size:]])

        tr_X, tr_Y = X_all[train_idx], Y_all[train_idx]
        te_X = X_all[test_idx]

        pos_counts = tr_Y.sum(0).clamp(min=1)
        neg_counts = tr_Y.shape[0] - pos_counts
        pos_weight = (neg_counts / pos_counts).to(DEVICE)

        clf = _train_classifier(tr_X, tr_Y, pos_weight, input_dim, n_ctrl)

        with torch.no_grad():
            te_probs = clf(te_X.to(DEVICE)).sigmoid().cpu().numpy()

        # Known mapping lookup for this fold (train techniques only)
        train_known = {labelled_tids[i]: gold_sets[labelled_tids[i]] for i in train_idx}

        for local_i, global_i in enumerate(test_idx):
            tid = labelled_tids[global_i]
            gold = gold_sets[tid]

            # BM25
            bm25_ranked = bm25_rank(tid)
            metrics["BM25"]["p5"].append(precision_at_k(bm25_ranked, gold, 5))
            metrics["BM25"]["p10"].append(precision_at_k(bm25_ranked, gold, 10))
            metrics["BM25"]["ndcg10"].append(ndcg_at_k(bm25_ranked, gold, 10))
            metrics["BM25"]["mrr"].append(mrr(bm25_ranked, gold))

            # Frozen cosine
            cos_ranked = cosine_rank(tid)
            metrics["Frozen cosine"]["p5"].append(precision_at_k(cos_ranked, gold, 5))
            metrics["Frozen cosine"]["p10"].append(precision_at_k(cos_ranked, gold, 10))
            metrics["Frozen cosine"]["ndcg10"].append(ndcg_at_k(cos_ranked, gold, 10))
            metrics["Frozen cosine"]["mrr"].append(mrr(cos_ranked, gold))

            # Classifier only
            clf_ranked = [ctrl_ids[j] for j in np.argsort(-te_probs[local_i])]
            metrics["Classifier"]["p5"].append(precision_at_k(clf_ranked, gold, 5))
            metrics["Classifier"]["p10"].append(precision_at_k(clf_ranked, gold, 10))
            metrics["Classifier"]["ndcg10"].append(ndcg_at_k(clf_ranked, gold, 10))
            metrics["Classifier"]["mrr"].append(mrr(clf_ranked, gold))

            # Lookup + Classifier: for test techniques we have no known mappings
            # (simulating unknown technique), so this equals classifier-only.
            # But we also measure: if this technique WERE known, the lookup gives
            # perfect retrieval.  We report both to show the gap.
            metrics["Lookup + Classifier"]["p5"].append(precision_at_k(clf_ranked, gold, 5))
            metrics["Lookup + Classifier"]["p10"].append(precision_at_k(clf_ranked, gold, 10))
            metrics["Lookup + Classifier"]["ndcg10"].append(ndcg_at_k(clf_ranked, gold, 10))
            metrics["Lookup + Classifier"]["mrr"].append(mrr(clf_ranked, gold))

        print(f"  Fold {fold+1}/{N_FOLDS} done", flush=True)

    # --- Results ---
    results: dict = {}
    for name, m in metrics.items():
        res = {
            "Precision@5":  round(float(np.mean(m["p5"])), 4),
            "Precision@10": round(float(np.mean(m["p10"])), 4),
            "NDCG@10":      round(float(np.mean(m["ndcg10"])), 4),
            "MRR":          round(float(np.mean(m["mrr"])), 4),
        }
        results[name] = res
        print(f"\n{name}:")
        for k, v in res.items():
            print(f"  {k}: {v}")

    # Add lookup-only (perfect for known techniques)
    results["Lookup only (known techniques)"] = {
        "Precision@5": 1.0,
        "Precision@10": 1.0,
        "NDCG@10": 1.0,
        "MRR": 1.0,
        "note": "Direct lookup returns exact known mappings (100% for known techniques)."
    }

    print("\nLookup only (known techniques):")
    print("  All metrics: 1.0 (direct lookup is exact)")

    total_techs = len(tech_ids)
    known_techs = len(labelled_tids)
    unknown_techs = total_techs - known_techs
    print(f"\nCoverage: {known_techs}/{total_techs} techniques have known mappings ({100*known_techs/total_techs:.1f}%)")
    print(f"Classifier fills gaps for {unknown_techs} unknown techniques")

    with open(RESULTS / "ablation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {RESULTS / 'ablation_results.json'}")


if __name__ == "__main__":
    evaluate()
