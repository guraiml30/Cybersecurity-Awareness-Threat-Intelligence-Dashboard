# 🛡️ Cybersecurity Awareness & Threat Intelligence Dashboard

A **defensive** Streamlit dashboard that collects, scores, visualizes and explains threat intelligence while teaching users to recognize common threats. Runs fully offline on **synthetic data**.

## Safety by design
- No scanning, probing, exploitation, malware, phishing pages or payloads
- Indicators are **text only**: never resolved, fetched or contacted
- IPs use RFC 5737 ranges, domains use reserved TLDs (`.example/.invalid/.test`), CVEs are fictional (`CVE-2099-xxxx`), indicators are defanged

## Observation vs Indicator vs Alert vs Threat vs Incident
| Level | Meaning |
|---|---|
| OBSERVATION | Raw, low-confidence data point |
| INDICATOR | Trackable observable with decent confidence |
| ALERT | Indicator also seen internally + meaningful score |
| THREAT | Multi-source corroborated, high confidence, high score |
| INCIDENT | Impact confirmed by a human analyst (never granted by score alone) |

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python runall.py          # generate data -> run tests -> launch dashboard
```
Other options: `python runall.py --no-launch`, `--skip-tests`, `--records 500`.

## Features (all 20 requested)
Threat feed, IOC dashboard, category analysis, IP/domain/URL/hash indicator analysis, CVE awareness, severity scoring (explainable 0-100), trends, MITRE ATT&CK mapping, alerts, search, filtering, learning center, quizzes, awareness score, incident guidance, SOC investigation view, executive summary.

## Scoring (0-100)
`category risk (0-40) + confidence (0-30) + sightings (0-20) + asset criticality (0-10) [+10 if exploitation reported]`.
Severity: <30 INFORMATIONAL, <45 LOW, <60 MEDIUM, <80 HIGH, else CRITICAL.

## Project layout
```
app.py            Streamlit dashboard (11 pages)
runall.py         One-command setup/run
src/              taxonomy, generate_data, scoring, analysis, learning
tests/            unit tests (python -m unittest discover tests)
data/             generated synthetic data
```

## Ideas to extend
Add a CSV import for your own sanitized data, a PDF export of the executive summary, or a Dockerfile.

## License
MIT. See [LICENSE](LICENSE). Replace `<YOUR NAME>` in it.
