"""Severity scoring and lifecycle classification (OBSERVATION -> INCIDENT)."""
from .taxonomy import ATTACK_MAP, CATEGORY_WEIGHT


def score_breakdown(r):
    """Return the explainable parts of a 0-100 risk score."""
    cat = round(r["cvss"] * 4) if r["indicator_type"] == "CVE ID" else CATEGORY_WEIGHT[r["category"]]
    parts = {
        "category_risk (0-40)": cat,
        "confidence (0-30)": round(r["confidence"] * 0.3),
        "sightings (0-20)": min(r["sightings"], 10) * 2,
        "asset_criticality (0-10)": r["asset_criticality"] * 2,
    }
    if r.get("exploitation_reported"):
        parts["exploitation_reported (+10)"] = 10
    return parts


def score_record(r):
    return min(100, sum(score_breakdown(r).values()))


def severity_from_score(score):
    for limit, name in [(30, "INFORMATIONAL"), (45, "LOW"), (60, "MEDIUM"), (80, "HIGH")]:
        if score < limit:
            return name
    return "CRITICAL"


def classify_lifecycle(r, score):
    """Returns (level, reason). INCIDENT is never granted by score alone."""
    if r["impact_confirmed"]:
        return "INCIDENT", "An analyst confirmed real impact."
    if r["corroborating_sources"] >= 2 and r["confidence"] >= 70 and score >= 60:
        return "THREAT", f"{r['corroborating_sources']} sources agree, confidence {r['confidence']}, score {score}."
    if r["seen_internally"] and score >= 35:
        return "ALERT", f"Seen in our environment ({r['sightings']} sightings) with score {score}."
    if r["confidence"] >= 50:
        return "INDICATOR", f"Confidence {r['confidence']} is high enough to track, but no internal match yet."
    return "OBSERVATION", f"Confidence only {r['confidence']} and not corroborated."


def enrich(records):
    out = []
    for r in records:
        s = score_record(r)
        level, why = classify_lifecycle(r, s)
        out.append({**r, "score": s, "severity": severity_from_score(s), "lifecycle": level,
                    "lifecycle_reason": why,
                    "techniques": [t[0] for t in ATTACK_MAP[r["category"]]]})
    return out
