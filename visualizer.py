import ast
import os
import re

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Python Mini IDS Dashboard", layout="wide")
st.title("Python Mini IDS Dashboard")

ALERTS_CSV = "alerts.csv"
COLUMNS = ["timestamp", "threat_type", "source_ip", "destination_ip",
           "confidence", "details"]


@st.cache_data(ttl=5)
def load_alerts():
    if not os.path.exists(ALERTS_CSV) or os.path.getsize(ALERTS_CSV) == 0:
        return pd.DataFrame(columns=COLUMNS)

    # alert_system.py only writes a header when the file is new, so a file that
    # survived across runs may have none. Force our own column names.
    df = pd.read_csv(ALERTS_CSV, header=None, names=COLUMNS)

    # A stale header row (literally the word "timestamp") can be sitting mid-file
    # from an earlier run; drop any such rows.
    df = df[df["timestamp"] != "timestamp"]

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    # 'details' is a Python-dict string; pull out the rule/method as one label.
    # Older rows may contain np.float64(...) wrappers, which ast.literal_eval
    # rejects; strip them to a bare number first so those rows still parse.
    def label(details):
        cleaned = re.sub(r"np\.float64\(([^)]*)\)", r"\1", str(details))
        try:
            d = ast.literal_eval(cleaned)
            return d.get("rule") or d.get("method") or d.get("type") or "unknown"
        except (ValueError, SyntaxError):
            return "unknown"

    df["detector"] = df["details"].apply(label)
    return df


# This fragment re-runs on its own every 3 seconds, re-reading alerts.csv, so
# the dashboard updates live while the IDS writes to the file. Streamlit does
# not auto-refresh otherwise — a plain script runs once and then sits idle.
@st.fragment(run_every=3)
def dashboard():
    df = load_alerts()

    if df.empty:
        st.info("No alerts yet. Start the IDS (sudo ./venv/bin/python src.py "
                "--baseline-pcap baseline.pcap). This refreshes automatically.")
        return

    # Signature detectors are real attacks (not anomaly noise) — surface them.
    ATTACKS = {
        "arp_spoofing": "ARP SPOOFING",
        "port_scan": "PORT SCAN",
        "syn_flood": "SYN FLOOD",
    }
    attacks = df[df["detector"].isin(ATTACKS)]

    # Clean, readable column labels for the tables.
    LABELS = {
        "timestamp": "Time",
        "detector": "Detector",
        "source_ip": "Source IP",
        "destination_ip": "Destination IP",
        "confidence": "Confidence",
        "details": "Details",
    }

    def show_table(frame, cols):
        st.dataframe(frame[cols].rename(columns=LABELS),
                     width="stretch", hide_index=True)

    # --- Top-line metrics -----------------------------------------------------
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total alerts", len(df))
    c2.metric("Attack alerts", len(attacks))
    c3.metric("Unique source IPs", df["source_ip"].nunique())
    c4.metric("High confidence (>0.8)", int((df["confidence"] > 0.8).sum()))

    # Call out each attack type loudly, with its own red banner.
    for detector, name in ATTACKS.items():
        hits = df[df["detector"] == detector]
        if not hits.empty:
            st.error(f"{name} DETECTED — {len(hits)} alert(s)")
            show_table(hits.sort_values("timestamp", ascending=False).head(20),
                       ["timestamp", "source_ip", "details"])

    # --- Alerts by detector ---------------------------------------------------
    # horizontal=True puts the category labels on the y-axis, where they read
    # left-to-right instead of being rotated vertically on the x-axis.
    st.subheader("Alerts by detector")
    st.bar_chart(df["detector"].value_counts(), horizontal=True)

    # --- Top source IPs -------------------------------------------------------
    st.subheader("Top 10 source IPs by alert count")
    st.bar_chart(df["source_ip"].value_counts().head(10), horizontal=True)

    # --- Alerts over time -----------------------------------------------------
    st.subheader("Alerts over time")
    over_time = df.set_index("timestamp").resample("5s").size()
    st.line_chart(over_time)

    # --- Raw feed -------------------------------------------------------------
    st.subheader("Recent alerts")
    show_table(
        df.sort_values("timestamp", ascending=False).head(200),
        ["timestamp", "detector", "source_ip", "destination_ip", "confidence"],
    )


dashboard()
