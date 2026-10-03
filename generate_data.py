"""Generates 100% synthetic threat data. Nothing here is real or routable.

Safe-by-design choices:
  * IPs come from RFC 5737 documentation ranges (never real hosts)
  * Domains use reserved TLDs (.example/.invalid/.test)
  * Indicators are stored DEFANGED (hxxp, [.]) so they cannot be clicked by accident
  * File hashes are hashes of dummy strings - they match no real file
  * CVE IDs use the fictional CVE-2099-xxxx range
"""
import hashlib, json, random
from datetime import datetime, timedelta
from pathlib import Path

TYPE_TO_CATEGORIES = {
    "IP ADDRESS": ["NETWORK THREATS", "CREDENTIAL THREATS", "MALWARE", "WEB THREATS", "ACCOUNT SECURITY", "DATA EXPOSURE"],
    "DOMAIN": ["PHISHING", "MALWARE", "WEB THREATS", "SOCIAL ENGINEERING", "RANSOMWARE"],
    "URL": ["PHISHING", "WEB THREATS", "MALWARE", "SOCIAL ENGINEERING", "CREDENTIAL THREATS", "DATA EXPOSURE"],
    "FILE HASH": ["MALWARE", "RANSOMWARE"],
    "EMAIL/SENDER DOMAIN": ["PHISHING", "SOCIAL ENGINEERING", "ACCOUNT SECURITY"],
    "CVE ID": ["VULNERABILITY EXPOSURE"],
}
SOURCES = ["Synthetic Feed A", "Synthetic Feed B", "Internal Sensor", "Awareness Reports", "Community Sample"]
WORDS = ["login", "secure", "verify", "update", "billing", "portal", "account", "support", "docs", "cloud", "mail", "pay"]
PATHS = ["verify", "reset", "invoice", "update", "download", "session", "confirm"]
DESCRIPTIONS = {
    "PHISHING": "Lookalike page imitating a sign-in portal (synthetic).",
    "MALWARE": "Indicator linked to a fictional malware family sample.",
    "RANSOMWARE": "Indicator associated with a fictional ransomware campaign.",
    "CREDENTIAL THREATS": "Repeated failed-login pattern consistent with password guessing.",
    "WEB THREATS": "Suspicious web request pattern against a public application.",
    "NETWORK THREATS": "Port-sweep style activity seen by a network sensor.",
    "VULNERABILITY EXPOSURE": "Fictional vulnerability affecting a commonly deployed component.",
    "SOCIAL ENGINEERING": "Message pressuring the recipient to act urgently.",
    "DATA EXPOSURE": "Possible publicly reachable storage or leaked-data reference.",
    "ACCOUNT SECURITY": "Unusual sign-in or MFA-prompt pattern.",
}


def _indicator(rng, itype, i):
    word = rng.choice(WORDS) + "-" + "".join(rng.choices("abcdefghjkmnpqrstuvwxyz23456789", k=rng.randint(3, 8)))
    tld = rng.choice(["example", "invalid", "test"])
    if itype == "IP ADDRESS":
        net = rng.choice(["192.0.2", "198.51.100", "203.0.113"])
        return f"{net}.{rng.randint(1, 254)}".replace(".", "[.]")
    if itype == "DOMAIN":
        return f"{word}[.]{tld}"
    if itype == "URL":
        return f"hxxps://{word}[.]{tld}/{rng.choice(PATHS)}/{rng.randint(100, 999)}"
    if itype == "FILE HASH":
        algo = rng.choice(["md5", "sha1", "sha256"])
        return hashlib.new(algo, f"synthetic-sample-{i}".encode()).hexdigest()
    if itype == "EMAIL/SENDER DOMAIN":
        return f"{word}[.]{tld}"
    return f"CVE-2099-{rng.randint(1000, 9999)}"


def generate(n=300, seed=42):
    rng = random.Random(seed)
    now = datetime.now().replace(microsecond=0)
    out = []
    for i in range(1, n + 1):
        itype = rng.choice(list(TYPE_TO_CATEGORIES))
        cat = rng.choice(TYPE_TO_CATEGORIES[itype])
        sightings = rng.choice([0, 1, 1, 2, 3, 5, 8, 12])
        seen_internal = sightings >= 2 and rng.random() < 0.7
        first = now - timedelta(days=rng.randint(0, 89), hours=rng.randint(0, 23))
        last = min(now, first + timedelta(days=rng.randint(0, 10)))
        out.append({
            "id": f"TI-{i:04d}",
            "indicator_type": itype,
            "indicator": _indicator(rng, itype, i),
            "category": cat,
            "source": rng.choice(SOURCES),
            "corroborating_sources": rng.choice([1, 1, 1, 2, 2, 3, 4]),
            "confidence": rng.randint(10, 98),
            "sightings": sightings,
            "seen_internally": seen_internal,
            "asset_criticality": rng.randint(1, 5),
            "cvss": round(rng.uniform(3.0, 9.9), 1) if itype == "CVE ID" else 0.0,
            "exploitation_reported": itype == "CVE ID" and rng.random() < 0.3,
            # Only a human analyst can confirm impact -> deliberately rare.
            "impact_confirmed": seen_internal and sightings >= 5 and rng.random() < 0.1,
            "first_seen": first.isoformat(),
            "last_seen": last.isoformat(),
            "description": DESCRIPTIONS[cat],
        })
    return out


def save(path="data/threat_data.json", n=300, seed=42):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    data = generate(n, seed)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


if __name__ == "__main__":
    print(f"Wrote {len(save())} synthetic records to data/threat_data.json")
