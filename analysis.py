"""Static indicator analysis (string-only, NO network access) and summaries."""
import math, re
from collections import Counter

KEYWORDS = ["login", "secure", "verify", "update", "billing", "account", "support", "pay"]


def refang(s):
    """Only for parsing text. We never connect to anything."""
    return s.replace("[.]", ".").replace("hxxp", "http")


def entropy(s):
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values()) if s else 0.0


def analyze_indicator(itype, value):
    """Return a list of (finding, points) - heuristics, not verdicts."""
    v = refang(value.strip())
    f = []
    if itype == "IP ADDRESS":
        octs = v.split(".")
        if len(octs) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octs):
            return [("Not a valid IPv4 address", 0)]
        a, b = int(octs[0]), int(octs[1])
        if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
            f.append(("Private (RFC 1918) address: internal host, not an external threat source", 0))
        elif v.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
            f.append(("Documentation range (RFC 5737): synthetic example address", 0))
        else:
            f.append(("Public address: check reputation in a threat-intel platform", 5))
    elif itype in ("DOMAIN", "EMAIL/SENDER DOMAIN", "URL"):
        host = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
        if "@" in host:
            f.append(("'@' in URL authority can hide the real destination", 25))
            host = host.split("@")[-1]
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            f.append(("Raw IP used instead of a domain name", 20))
        label = host.split(".")[0]
        if host.startswith("xn--") or ".xn--" in host:
            f.append(("Punycode (possible lookalike characters)", 20))
        if host.count("-") >= 2:
            f.append(("Several hyphens in hostname", 10))
        if sum(ch.isdigit() for ch in label) >= 3:
            f.append(("Many digits in hostname", 10))
        if any(k in label for k in KEYWORDS):
            f.append(("Urgency/credential keyword in hostname", 15))
        if entropy(label) > 3.3 and len(label) > 10:
            f.append(("Random-looking hostname (high entropy)", 15))
        if host.count(".") >= 3:
            f.append(("Many subdomain levels", 10))
        if itype == "URL" and len(v) > 100:
            f.append(("Very long URL", 10))
        if host.endswith((".example", ".invalid", ".test")):
            f.append(("Reserved TLD: synthetic example, cannot resolve on the real internet", 0))
    elif itype == "FILE HASH":
        kinds = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
        if not re.fullmatch(r"[0-9a-fA-F]+", v) or len(v) not in kinds:
            return [("Not a valid MD5/SHA-1/SHA-256 hash", 0)]
        f.append((f"Valid {kinds[len(v)]} hash. Compare it against your own file inventory or an AV/EDR hash list", 0))
        if len(v) < 64:
            f.append(("MD5/SHA-1 are collision-prone; prefer SHA-256", 5))
    elif itype == "CVE ID":
        if re.fullmatch(r"CVE-\d{4}-\d{4,7}", v):
            f.append(("Valid CVE format. Check vendor advisory, CVSS and whether you run the affected product", 0))
        else:
            return [("Not a valid CVE ID", 0)]
    return f or [("No notable findings", 0)]


def executive_summary(rows):
    n = len(rows)
    if not n:
        return "No data available."
    lc = Counter(r["lifecycle"] for r in rows)
    sev = Counter(r["severity"] for r in rows)
    cats = Counter(r["category"] for r in rows).most_common(3)
    top = ", ".join(f"{c} ({k})" for c, k in cats)
    return (
        f"Of {n} tracked records, {lc['OBSERVATION']} are observations, {lc['INDICATOR']} are indicators, "
        f"{lc['ALERT']} are alerts, {lc['THREAT']} are corroborated threats and only {lc['INCIDENT']} are "
        f"confirmed incidents. {sev['CRITICAL']} records are CRITICAL and {sev['HIGH']} are HIGH severity. "
        f"The most frequent categories are {top}. Priority: triage ALERT/THREAT items first, "
        f"patch exploited vulnerabilities, and run awareness refreshers for the top categories."
    )
