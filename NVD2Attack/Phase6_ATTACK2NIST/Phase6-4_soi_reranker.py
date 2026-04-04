"""Phase 6-4  –  SOI Context Reranker.

Computes a context-aware boost for (technique, control) pairs based on:
  1. CVSS severity of CVEs originating from SOI components,
  2. Affinity between the SOI component type and the NIST control family.

The boost is designed to be *interpretable* and *auditable*:
each score delta can be traced back to a specific CVE, component, and
control family.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SOI_CVE_MAP = ROOT / "SysML2CVE" / "cve_mapping_output.json"


# ---------------------------------------------------------------------------
# Family affinity table
# ---------------------------------------------------------------------------
# Maps component-type keywords → control families that are especially
# relevant.  The multiplier *amplifies* the CVSS-based weight.  Everything
# not listed gets 1.0 (neutral).

FAMILY_AFFINITY: dict[str, dict[str, float]] = {
    "crypto":      {"SC": 1.5, "IA": 1.3},
    "auth":        {"AC": 1.5, "IA": 1.5, "AU": 1.3},
    "database":    {"AC": 1.4, "AU": 1.3, "SC": 1.3, "MP": 1.2},
    "webapp":      {"AC": 1.3, "SI": 1.3, "SC": 1.2},
    "api":         {"AC": 1.3, "SC": 1.3, "SI": 1.2},
    "os":          {"CM": 1.4, "SI": 1.4, "AC": 1.3, "SC": 1.3, "RA": 1.2},
    "container":   {"CM": 1.4, "SI": 1.3, "AC": 1.2},
    "broker":      {"SC": 1.3, "AU": 1.3, "AC": 1.2},
    "audit":       {"AU": 1.5, "SI": 1.3, "AC": 1.2},
}


def _classify_component(name: str) -> str:
    """Coarse classification of a SOI component by its name."""
    nl = name.lower()
    if "crypto" in nl or "tls" in nl or "ssl" in nl:
        return "crypto"
    if "auth" in nl:
        return "auth"
    if "data" in nl or "store" in nl or "db" in nl:
        return "database"
    if "web" in nl or "dashboard" in nl:
        return "webapp"
    if "api" in nl or "gateway" in nl or "proxy" in nl:
        return "api"
    if "os" in nl or "host" in nl or "edge" in nl:
        return "os"
    if "container" in nl or "docker" in nl:
        return "container"
    if "broker" in nl or "mqtt" in nl or "telemetry" in nl:
        return "broker"
    if "audit" in nl or "log" in nl:
        return "audit"
    return "generic"


def _control_family(cid: str) -> str:
    return cid.split("-")[0]


# ---------------------------------------------------------------------------
# SOI data loader
# ---------------------------------------------------------------------------

def load_soi_context(soi_path: str | Path | None = None) -> dict:
    """Parse SysML2CVE output into per-component summary.

    Returns dict {component_name: {type, cves: [{cve_id, cvss}], total_cvss}}
    """
    path = Path(soi_path) if soi_path else SOI_CVE_MAP
    with open(path) as f:
        raw = json.load(f)

    context: dict = {}
    for comp_name, comp_data in raw.items():
        ctype = _classify_component(comp_name)
        cves = []
        for cve in comp_data.get("matched_cves", []):
            score = cve.get("cvss_score") or 0.0
            cves.append({"cve_id": cve["cve_id"], "cvss": float(score),
                         "description": cve.get("description", "")})
        context[comp_name] = {
            "type": ctype,
            "cves": cves,
            "total_cvss": sum(c["cvss"] for c in cves),
        }
    return context


# ---------------------------------------------------------------------------
# Boost computation
# ---------------------------------------------------------------------------

def compute_soi_boost(
    control_id: str,
    soi_context: dict,
    technique_cve_ids: set[str] | None = None,
) -> tuple[float, list[dict]]:
    """Return (boost_score, justification_entries).

    If *technique_cve_ids* is provided, only CVEs matching those IDs contribute.
    Otherwise every CVE in the SOI contributes (system-wide relevance).
    """
    fam = _control_family(control_id)
    boost = 0.0
    justifications: list[dict] = []

    for comp_name, comp in soi_context.items():
        affinity = FAMILY_AFFINITY.get(comp["type"], {}).get(fam, 1.0)
        for cve in comp["cves"]:
            if technique_cve_ids and cve["cve_id"] not in technique_cve_ids:
                continue
            cvss_weight = cve["cvss"] / 10.0
            delta = cvss_weight * affinity
            boost += delta
            if delta > 0:
                justifications.append({
                    "component": comp_name,
                    "component_type": comp["type"],
                    "cve_id": cve["cve_id"],
                    "cvss": cve["cvss"],
                    "family_affinity": affinity,
                    "delta": round(delta, 4),
                })

    return round(boost, 4), justifications


# ---------------------------------------------------------------------------
# Convenience: vectorised boost for all controls at once
# ---------------------------------------------------------------------------

def compute_all_boosts(
    control_ids: list[str],
    soi_context: dict,
    technique_cve_ids: set[str] | None = None,
) -> tuple[list[float], dict[str, list[dict]]]:
    """Return (list_of_boosts, {ctrl_id: justification})."""
    boosts: list[float] = []
    justs: dict[str, list[dict]] = {}
    for cid in control_ids:
        b, j = compute_soi_boost(cid, soi_context, technique_cve_ids)
        boosts.append(b)
        justs[cid] = j
    return boosts, justs


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ctx = load_soi_context()
    print(f"SOI components: {len(ctx)}")
    for name, info in ctx.items():
        print(f"  {name}: type={info['type']}, CVEs={len(info['cves'])}, total_CVSS={info['total_cvss']:.1f}")

    sample_ctrl = "SC-12"
    boost, just = compute_soi_boost(sample_ctrl, ctx)
    print(f"\nBoost for {sample_ctrl}: {boost:.4f}")
    if just:
        print(f"  Top justifications: {just[:3]}")
