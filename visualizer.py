import ast
import os

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
    def label(details):
        try:
            d = ast.literal_eval(details)
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

    # --- Top-line metrics -----------------------------------------------------
    arp = df[df["detector"] == "arp_spoofing"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total alerts", len(df))
    c2.metric("ARP spoofing", len(arp))
    c3.metric("Unique source IPs", df["source_ip"].nunique())
    c4.metric("High confidence (>0.8)", int((df["confidence"] > 0.8).sum()))

    # ARP is the attack we specifically want to surface — call it out loudly.
    if not arp.empty:
        st.error(f"ARP SPOOFING DETECTED — {len(arp)} alert(s)")
        st.dataframe(arp[["timestamp", "source_ip", "details"]], width="stretch")

    # --- Alerts by detector ---------------------------------------------------
    st.subheader("Alerts by detector")
    st.bar_chart(df["detector"].value_counts())

    # --- Top source IPs -------------------------------------------------------
    st.subheader("Top 10 source IPs by alert count")
    st.bar_chart(df["source_ip"].value_counts().head(10))

    # --- Alerts over time -----------------------------------------------------
    st.subheader("Alerts over time")
    over_time = df.set_index("timestamp").resample("5s").size()
    st.line_chart(over_time)

    # --- Raw feed -------------------------------------------------------------
    st.subheader("Recent alerts")
    st.dataframe(
        df.sort_values("timestamp", ascending=False)
          .head(200)[["timestamp", "detector", "source_ip", "destination_ip", "confidence"]],
        width="stretch",
    )


dashboard()
