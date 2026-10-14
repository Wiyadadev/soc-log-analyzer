import streamlit as st
import pandas as pd
from pathlib import Path

REPORT_FILE = Path("soc_report.csv")

st.set_page_config(
    page_title="SOC Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC Log Analyzer Dashboard")
st.caption("Sysmon Event Monitoring & Risk Triage")

if not REPORT_FILE.exists():
    st.error("soc_report.csv not found")
    st.stop()

df = pd.read_csv(REPORT_FILE)

# -----------------------------
# SUMMARY
# -----------------------------

total = len(df)
low = len(df[df["risk"] == "LOW"])
review = len(df[df["risk"] == "REVIEW"])
suspicious = len(df[df["risk"] == "SUSPICIOUS"])

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", total)
col2.metric("LOW", low)
col3.metric("REVIEW", review)
col4.metric("SUSPICIOUS", suspicious)

st.divider()

# -----------------------------
# EVENT TYPES
# -----------------------------

st.subheader("Event Types")

event_counts = df["type"].value_counts()

st.bar_chart(event_counts)

# -----------------------------
# RISK DISTRIBUTION
# -----------------------------

st.subheader("Risk Distribution")

risk_counts = df["risk"].value_counts()

st.bar_chart(risk_counts)

# -----------------------------
# FILTER
# -----------------------------

st.subheader("Event Explorer")

risk_filter = st.multiselect(
    "Risk Level",
    ["LOW", "REVIEW", "SUSPICIOUS"],
    default=["LOW", "REVIEW", "SUSPICIOUS"]
)

type_filter = st.multiselect(
    "Event Type",
    sorted(df["type"].dropna().unique()),
    default=sorted(df["type"].dropna().unique())
)

filtered = df[
    df["risk"].isin(risk_filter)
    & df["type"].isin(type_filter)
]

st.dataframe(
    filtered,
    use_container_width=True,
    hide_index=True
)

# -----------------------------
# INVESTIGATION QUEUE
# -----------------------------

st.subheader("🔎 Investigation Queue")

investigation = df[
    df["risk"].isin(["REVIEW", "SUSPICIOUS"])
]

if len(investigation) == 0:
    st.success("No events currently require investigation.")
else:
    st.dataframe(
        investigation,
        use_container_width=True,
        hide_index=True
    )