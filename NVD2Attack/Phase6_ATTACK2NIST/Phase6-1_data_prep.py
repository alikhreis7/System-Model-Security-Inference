"""Phase 6-1  –  Data Preparation for ATT&CK → NIST 800-53 Control Mapping.

Strategy:
    * Known mappings are used as a direct lookup at inference time.
    * ALL 5,314 known pairs train the classifier (no train/test split needed
      for known techniques — the classifier only fills gaps).
    * A small held-out set of techniques is reserved for leave-one-out
      evaluation of the classifier's generalisation ability.
    * Frozen SecureBERT embeddings are used — no fine-tuning.

Outputs:
    data/technique_texts.json   – {technique_id: text_blob}
    data/control_texts.json     – {control_id:   text_blob}
    data/known_mappings.json    – {technique_id: [control_ids]}
    data/classifier_labels.json – {technique_id: [0/1 for each control]}
    data/all_control_ids.json   – ordered list of control IDs used as labels
    data/embeddings.pt          – frozen SecureBERT embeddings
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

import torch
import torch.nn.functional as F
from transformers import AutoModel, AutoTokenizer

ROOT = Path(__file__).resolve().parent.parent.parent
DATA_OUT = Path(__file__).resolve().parent / "data"
DATA_OUT.mkdir(exist_ok=True)

ATTACK_STIX = ROOT / "OSRs" / "ATTACK" / "enterprise-attack-v16.1.json"
NIST_JSON   = ROOT / "OSRs" / "NIST800_53" / "nist_800_53.json"
KNOWN_MAP   = ROOT / "OSRs" / "NIST800-53-layer-navigator" / "nist_800_53-rev5_attack-16.1-enterprise_json.json"

MODEL_NAME = "ehsanaghaei/SecureBERT"
MAX_LEN    = 128
DEVICE     = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ---------------------------------------------------------------------------
# ID normalisation  (AC-02 → AC-2)
# ---------------------------------------------------------------------------

def normalize_ctrl_id(cid: str) -> str:
    m = re.match(r"([A-Z]+)-0*(\d+)(.*)", cid)
    return f"{m.group(1)}-{m.group(2)}{m.group(3)}" if m else cid


# ---------------------------------------------------------------------------
# 1.  Technique text corpus
# ---------------------------------------------------------------------------

def _strip_markdown_links(text: str) -> str:
    return re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)


def build_technique_texts() -> dict[str, str]:
    with open(ATTACK_STIX) as f:
        stix = json.load(f)

    techniques: dict[str, str] = {}
    for obj in stix["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        tid = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref["external_id"]
                break
        if tid is None:
            continue

        name = obj.get("name", "")
        desc = _strip_markdown_links(obj.get("description", ""))
        detect = _strip_markdown_links(obj.get("x_mitre_detection", "") or "")
        platforms = ", ".join(obj.get("x_mitre_platforms", []))
        tactics = ", ".join(
            p["phase_name"] for p in obj.get("kill_chain_phases", [])
        )

        blob = f"{tid} {name}"
        if tactics:
            blob += f" | tactics: {tactics}"
        if platforms:
            blob += f" | platforms: {platforms}"
        if desc:
            blob += f" | {desc}"
        if detect:
            blob += f" | detection: {detect}"

        techniques[tid] = blob

    return techniques


# ---------------------------------------------------------------------------
# 2.  Control text corpus
# ---------------------------------------------------------------------------

def build_control_texts() -> dict[str, str]:
    with open(NIST_JSON) as f:
        controls_raw = json.load(f)

    controls: dict[str, str] = {}
    for c in controls_raw:
        cid = c["control_id"]
        name = c.get("name", "")
        stmt = c.get("statement", "")
        disc = c.get("discussion", "")

        blob = f"{cid} {name}"
        if stmt:
            blob += f" | {stmt}"
        if disc:
            blob += f" | {disc}"

        controls[cid] = blob

    return controls


# ---------------------------------------------------------------------------
# 3.  Known mappings  (with ID normalisation)
# ---------------------------------------------------------------------------

def load_known_mappings(nist_ctrl_ids: set[str]) -> tuple[dict[str, list[str]], dict[str, dict[str, str]]]:
    """Return (tech→[ctrl_ids], tech→{ctrl_id: comment})."""
    with open(KNOWN_MAP) as f:
        raw = json.load(f)

    tech_to_ctrls: dict[str, list[str]] = defaultdict(list)
    tech_ctrl_comments: dict[str, dict[str, str]] = defaultdict(dict)

    for m in raw["mapping_objects"]:
        if m["mapping_type"] != "mitigates":
            continue
        tid = m["attack_object_id"]
        raw_cid = m["capability_id"]
        if tid is None or raw_cid is None:
            continue
        cid = normalize_ctrl_id(raw_cid)
        if cid not in nist_ctrl_ids:
            continue
        tech_to_ctrls[tid].append(cid)
        tech_ctrl_comments[tid][cid] = m.get("comments", "")

    return dict(tech_to_ctrls), dict(tech_ctrl_comments)


# ---------------------------------------------------------------------------
# 4.  Classifier label matrix  (ALL known pairs, no split)
# ---------------------------------------------------------------------------

def build_label_matrix(
    tech_to_ctrls: dict[str, list[str]],
    all_ctrl_ids: list[str],
) -> dict[str, list[int]]:
    """Return {technique_id: [0/1 for each control]}."""
    ctrl_idx = {c: i for i, c in enumerate(all_ctrl_ids)}
    n = len(all_ctrl_ids)

    labels: dict[str, list[int]] = {}
    for tid, cids in tech_to_ctrls.items():
        row = [0] * n
        for cid in cids:
            if cid in ctrl_idx:
                row[ctrl_idx[cid]] = 1
        labels[tid] = row

    return labels


# ---------------------------------------------------------------------------
# 5.  Frozen SecureBERT embeddings
# ---------------------------------------------------------------------------

@torch.no_grad()
def _batch_encode(model, tokenizer, texts: list[str], batch_size: int = 32) -> torch.Tensor:
    all_embs = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        enc = tokenizer(batch, padding=True, truncation=True,
                        max_length=MAX_LEN, return_tensors="pt").to(DEVICE)
        out = model(input_ids=enc["input_ids"], attention_mask=enc["attention_mask"])
        mask = enc["attention_mask"].unsqueeze(-1).expand(out.last_hidden_state.size()).float()
        pooled = (out.last_hidden_state * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
        emb = F.normalize(pooled, dim=-1)
        all_embs.append(emb.cpu())
        if i % 200 == 0:
            print(f"  encoded {i}/{len(texts)}", flush=True)
    return torch.cat(all_embs, dim=0)


def build_embeddings(tech_texts: dict[str, str], ctrl_texts: dict[str, str]) -> None:
    print("Loading frozen SecureBERT …")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModel.from_pretrained(MODEL_NAME).to(DEVICE).eval()

    tech_ids = sorted(tech_texts.keys())
    ctrl_ids = sorted(ctrl_texts.keys())

    print(f"Encoding {len(tech_ids)} techniques …")
    tech_embs = _batch_encode(model, tokenizer, [tech_texts[t] for t in tech_ids])
    print(f"Encoding {len(ctrl_ids)} controls …")
    ctrl_embs = _batch_encode(model, tokenizer, [ctrl_texts[c] for c in ctrl_ids])

    torch.save({
        "technique_ids": tech_ids,
        "control_ids": ctrl_ids,
        "technique_embeddings": tech_embs,
        "control_embeddings": ctrl_embs,
    }, DATA_OUT / "embeddings.pt")
    print(f"Saved embeddings: {tech_embs.shape}, {ctrl_embs.shape}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("Building technique texts …")
    tech_texts = build_technique_texts()
    print(f"  {len(tech_texts)} techniques")

    print("Building control texts …")
    ctrl_texts = build_control_texts()
    print(f"  {len(ctrl_texts)} controls")

    nist_ctrl_ids = set(ctrl_texts.keys())

    print("Loading known mappings (with ID normalisation) …")
    tech_to_ctrls, tech_ctrl_comments = load_known_mappings(nist_ctrl_ids)
    total_pairs = sum(len(v) for v in tech_to_ctrls.values())
    mapped_ctrls = set(c for cs in tech_to_ctrls.values() for c in cs)
    print(f"  {total_pairs} pairs, {len(tech_to_ctrls)} techniques → {len(mapped_ctrls)} unique controls")

    all_ctrl_ids = sorted(ctrl_texts.keys())

    print("Building classifier label matrix (ALL pairs) …")
    labels = build_label_matrix(tech_to_ctrls, all_ctrl_ids)
    print(f"  {len(labels)} labelled techniques × {len(all_ctrl_ids)} controls")

    print("Building frozen SecureBERT embeddings …")
    build_embeddings(tech_texts, ctrl_texts)

    for name, obj in [
        ("technique_texts.json", tech_texts),
        ("control_texts.json", ctrl_texts),
        ("known_mappings.json", tech_to_ctrls),
        ("known_comments.json", tech_ctrl_comments),
        ("classifier_labels.json", labels),
        ("all_control_ids.json", all_ctrl_ids),
    ]:
        with open(DATA_OUT / name, "w") as f:
            json.dump(obj, f, indent=2)
        print(f"  wrote {name}")

    print("Done.")


if __name__ == "__main__":
    main()
