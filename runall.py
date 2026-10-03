#!/usr/bin/env python3
"""One command to set up and run everything:  python runall.py

Steps: 1) generate synthetic data  2) run tests  3) print a text summary  4) launch the dashboard.
Options: --no-launch (skip the dashboard), --skip-tests, --records N
"""
import argparse, subprocess, sys, unittest
from collections import Counter

from src.generate_data import save
from src.scoring import enrich

import subprocess, sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
subprocess.run(
    [sys.executable, "-m", "streamlit", "run", str(BASE / "app.py")],
    cwd=BASE,
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-launch", action="store_true")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--records", type=int, default=300)
    a = ap.parse_args()

    print("[1/4] Generating synthetic threat data ...")
    rows = enrich(save(n=a.records))
    print(f"      {len(rows)} records written to data/threat_data.json")

    if not a.skip_tests:
        print("[2/4] Running tests ...")
        res = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.discover("tests"))
        if not res.wasSuccessful():
            sys.exit("Tests failed - fix them before launching.")
    else:
        print("[2/4] Tests skipped.")

    print("[3/4] Summary")
    for title, key in [("Lifecycle", "lifecycle"), ("Severity", "severity")]:
        print(f"      {title}: " + ", ".join(f"{k}={v}" for k, v in Counter(r[key] for r in rows).most_common()))

    if a.no_launch:
        print("[4/4] Launch skipped. Start later with: streamlit run app.py")
        return
    try:
        import streamlit  # noqa: F401
    except ImportError:
        sys.exit("[4/4] Streamlit missing. Run: pip install -r requirements.txt  then  python runall.py")
    print("[4/4] Launching dashboard (Ctrl+C to stop) ...")
    subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py"])


if __name__ == "__main__":
    main()
