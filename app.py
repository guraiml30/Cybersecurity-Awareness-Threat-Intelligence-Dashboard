"""Cybersecurity Awareness & Threat Intelligence Dashboard (Streamlit). Run: streamlit run app.py"""
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from src.analysis import analyze_indicator, executive_summary
from src.generate_data import generate
from src.learning import INCIDENT_GUIDANCE, LESSONS, QUIZ, RECOMMENDED_ACTIONS, awareness_level
from src.scoring import enrich, score_breakdown
from src.taxonomy import (ATTACK_MAP, CATEGORIES, INDICATOR_TYPES, LIFECYCLE, LIFECYCLE_HELP, SEVERITIES)

st.set_page_config(page_title="Cyber Awareness & Threat Intel", page_icon="🛡️", layout="wide")


@st.cache_data
def load():
    p = Path("data/threat_data.json")
    raw = json.loads(p.read_text()) if p.exists() else generate()
    df = pd.DataFrame(enrich(raw))
    df["first_seen"] = pd.to_datetime(df["first_seen"])
    df["last_seen"] = pd.to_datetime(df["last_seen"])
    df["severity"] = pd.Categorical(df["severity"], SEVERITIES, ordered=True)
    df["lifecycle"] = pd.Categorical(df["lifecycle"], LIFECYCLE, ordered=True)
    return df


df = load()
st.sidebar.title("🛡️ CTI & Awareness")
st.sidebar.caption("Synthetic, defensive-only data. Nothing is ever contacted.")
page = st.sidebar.radio("Go to", [
    "Executive Summary", "Threat Feed (search & filter)", "IOC Dashboard", "Indicator Analysis",
    "Trends", "Vulnerabilities (CVE)", "MITRE ATT&CK", "Security Alerts", "SOC Investigation",
    "Learning Center", "Quiz & Awareness Score"])
SHOW = ["id", "indicator_type", "indicator", "category", "severity", "lifecycle", "score", "confidence", "sightings", "last_seen"]


def lifecycle_legend():
    with st.expander("What do OBSERVATION / INDICATOR / ALERT / THREAT / INCIDENT mean?"):
        for k in LIFECYCLE:
            st.markdown(f"**{k}**: {LIFECYCLE_HELP[k]}")


if page == "Executive Summary":
    st.title("Executive Cybersecurity Summary")
    st.write(executive_summary(df.to_dict("records")))
    cols = st.columns(5)
    for c, lvl in zip(cols, LIFECYCLE):
        c.metric(lvl, int((df.lifecycle == lvl).sum()))
    a, b = st.columns(2)
    a.subheader("Severity"); a.bar_chart(df.severity.value_counts().reindex(SEVERITIES))
    b.subheader("Top categories"); b.bar_chart(df.category.value_counts())
    lifecycle_legend()
    st.download_button("Download full dataset (CSV)", df.to_csv(index=False), "threat_data_scored.csv")

elif page == "Threat Feed (search & filter)":
    st.title("Threat Intelligence Feed")
    q = st.text_input("Search (ID, indicator, description)")
    c1, c2, c3, c4 = st.columns(4)
    cat = c1.multiselect("Category", CATEGORIES)
    sev = c2.multiselect("Severity", SEVERITIES)
    typ = c3.multiselect("Indicator type", INDICATOR_TYPES)
    lc = c4.multiselect("Lifecycle", LIFECYCLE)
    mn = st.slider("Minimum score", 0, 100, 0)
    v = df[df.score >= mn]
    for col, sel in [("category", cat), ("severity", sev), ("indicator_type", typ), ("lifecycle", lc)]:
        if sel:
            v = v[v[col].isin(sel)]
    if q:
        m = v[["id", "indicator", "description"]].apply(lambda s: s.str.contains(q, case=False, regex=False)).any(axis=1)
        v = v[m]
    st.caption(f"{len(v)} of {len(df)} records")
    st.dataframe(v.sort_values("score", ascending=False)[SHOW + ["source", "description"]], use_container_width=True, hide_index=True)
    lifecycle_legend()

elif page == "IOC Dashboard":
    st.title("IOC Dashboard")
    st.caption("An IOC is a lead, not proof of an attack. Check the lifecycle column.")
    a, b = st.columns(2)
    a.subheader("By indicator type"); a.bar_chart(df.indicator_type.value_counts())
    b.subheader("By lifecycle"); b.bar_chart(df.lifecycle.value_counts().reindex(LIFECYCLE))
    st.subheader("Category x severity")
    st.dataframe(pd.crosstab(df.category, df.severity), use_container_width=True)
    st.subheader("Top 15 by score")
    st.dataframe(df.nlargest(15, "score")[SHOW], use_container_width=True, hide_index=True)

elif page == "Indicator Analysis":
    st.title("Indicator Analysis (offline, string-only)")
    st.info("Analysis runs on the text only. The app never resolves, fetches or connects to any indicator.")
    t = st.selectbox("Indicator type", INDICATOR_TYPES)
    sample = df[df.indicator_type == t].iloc[0]["indicator"]
    val = st.text_input("Indicator (defanged recommended)", sample)
    if val:
        res = analyze_indicator(t, val)
        st.metric("Heuristic suspicion points", min(100, sum(p for _, p in res)))
        for text, pts in res:
            st.write(f"- {text}" + (f"  (+{pts})" if pts else ""))
        st.caption("Heuristics hint where to look. They are not a verdict.")
    st.subheader(f"Known {t} records")
    st.dataframe(df[df.indicator_type == t][SHOW].sort_values("score", ascending=False), use_container_width=True, hide_index=True)

elif page == "Trends":
    st.title("Threat Trends")
    w = df.set_index("first_seen")
    weekly = w.groupby([pd.Grouper(freq="W"), "category"], observed=True).size().unstack(fill_value=0)
    st.subheader("New records per week by category"); st.line_chart(weekly)
    sev = w.groupby([pd.Grouper(freq="W"), "severity"], observed=True).size().unstack(fill_value=0)
    st.subheader("New records per week by severity"); st.bar_chart(sev)

elif page == "Vulnerabilities (CVE)":
    st.title("Vulnerability / CVE Awareness")
    st.caption("CVE IDs here are fictional (CVE-2099-xxxx).")
    v = df[df.indicator_type == "CVE ID"]
    c1, c2 = st.columns(2)
    c1.metric("CVEs tracked", len(v)); c2.metric("Exploitation reported", int(v.exploitation_reported.sum()))
    st.bar_chart(pd.cut(v.cvss, [0, 4, 7, 9, 10], labels=["Low <4", "Medium 4-7", "High 7-9", "Critical 9+"]).value_counts())
    st.dataframe(v.sort_values(["exploitation_reported", "cvss"], ascending=False)[["id", "indicator", "cvss", "exploitation_reported", "score", "severity", "lifecycle"]], use_container_width=True, hide_index=True)
    st.success("Patch priority: exploited and exposed first, then highest CVSS on your most critical assets.")

elif page == "MITRE ATT&CK":
    st.title("MITRE ATT&CK Mapping")
    rows = [(c, t, n, tac, int((df.category == c).sum())) for c, ts in ATTACK_MAP.items() for t, n, tac in ts]
    m = pd.DataFrame(rows, columns=["category", "technique", "name", "tactic", "records"])
    st.bar_chart(m.groupby("tactic").records.sum())
    sel = st.multiselect("Filter category", CATEGORIES)
    st.dataframe(m[m.category.isin(sel)] if sel else m, use_container_width=True, hide_index=True)
    st.caption("Mapping is category-level and for learning. Real mapping needs observed behaviour.")

elif page == "Security Alerts":
    st.title("Security Alerts")
    st.caption("ALERT = seen in our environment + significant score. Needs triage, not panic.")
    a = df[df.lifecycle == "ALERT"].sort_values("score", ascending=False)
    st.metric("Open alerts", len(a))
    st.dataframe(a[SHOW + ["lifecycle_reason"]], use_container_width=True, hide_index=True)

elif page == "SOC Investigation":
    st.title("SOC Investigation View")
    rid = st.selectbox("Select a record", df.sort_values("score", ascending=False).id)
    r = df[df.id == rid].iloc[0]
    c1, c2, c3 = st.columns(3)
    c1.metric("Lifecycle", r.lifecycle); c2.metric("Severity", str(r.severity)); c3.metric("Score", int(r.score))
    st.write(f"**Indicator:** `{r.indicator}` ({r.indicator_type})  \n**Category:** {r.category}  \n**Why this level:** {r.lifecycle_reason}")
    st.write(f"First seen {r.first_seen:%Y-%m-%d %H:%M}, last seen {r.last_seen:%Y-%m-%d %H:%M}, {r.sightings} sightings, {r.corroborating_sources} source(s), asset criticality {r.asset_criticality}/5.")
    st.subheader("Score breakdown")
    st.bar_chart(pd.Series(score_breakdown(r.to_dict())))
    st.subheader("ATT&CK techniques")
    st.table(pd.DataFrame(ATTACK_MAP[r.category], columns=["ID", "Technique", "Tactic"]))
    st.subheader("Recommended defensive actions")
    for x in RECOMMENDED_ACTIONS[r.category]:
        st.write(f"- {x}")
    st.text_area("Analyst notes (this session only)", key=f"notes_{rid}")
    if r.lifecycle != "INCIDENT":
        st.info("Not an incident: no analyst has confirmed impact.")

elif page == "Learning Center":
    st.title("Awareness Learning Center")
    cat = st.selectbox("Threat category", CATEGORIES)
    what, signs, dos = LESSONS[cat]
    st.write(f"**What it is:** {what}")
    st.write("**Warning signs:**"); [st.write(f"- {s}") for s in signs]
    st.write("**What to do:**"); [st.write(f"- {s}") for s in dos]
    st.subheader("If you think something happened")
    for s in INCIDENT_GUIDANCE:
        st.write(s)

else:
    st.title("Security Quiz & Awareness Score")
    with st.form("quiz"):
        answers = [st.radio(f"{i+1}. {q}", opts, index=None, key=f"q{i}") for i, (q, opts, _, _) in enumerate(QUIZ)]
        done = st.form_submit_button("Submit")
    if done:
        correct = sum(a is not None and QUIZ[i][1].index(a) == QUIZ[i][2] for i, a in enumerate(answers))
        pct = round(100 * correct / len(QUIZ))
        st.metric("Awareness score", f"{pct}%", awareness_level(pct))
        for i, (q, opts, ans, why) in enumerate(QUIZ):
            ok = answers[i] is not None and opts.index(answers[i]) == ans
            st.write(f"{'✅' if ok else '❌'} Q{i+1}: {why}")
