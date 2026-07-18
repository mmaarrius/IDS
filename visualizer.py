import ast
import base64
import math
import os
import re
import struct
import time
import wave
from io import BytesIO

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Python Mini IDS Dashboard", layout="wide")
st.title("Python Mini IDS Dashboard")

ALERTS_CSV = "alerts.csv"
COLUMNS = ["timestamp", "threat_type", "source_ip", "destination_ip",
           "confidence", "details"]

# How long a war meme stays on screen before a newer red alert can replace it.
# A burst of alerts lets the current meme finish instead of flickering.
MEME_HOLD_SECONDS = 8

# Drop your own meme images (png/jpg/jpeg/gif/webp) into this folder; they are
# shown in rotation when an attack is detected. No code changes needed.
MEME_DIR = "memes"
MEME_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".webp")
MIME = {".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".gif": "gif", ".webp": "webp"}

@st.cache_data(ttl=10)
def load_meme_uris():
    """Meme images from MEME_DIR as data URIs (so they embed in the overlay)."""
    uris = []
    if os.path.isdir(MEME_DIR):
        for name in sorted(os.listdir(MEME_DIR)):
            ext = os.path.splitext(name)[1].lower()
            if ext in MEME_EXTS:
                with open(os.path.join(MEME_DIR, name), "rb") as f:
                    b64 = base64.b64encode(f.read()).decode()
                uris.append(f"data:image/{MIME[ext]};base64,{b64}")
    return uris


def alarm_sound_data_uri(repeats=3):
    """A two-tone alarm, repeated `repeats` times with a short gap between, as an
    inline WAV data URI (no external files) so one <audio> plays all repeats."""
    rate = 44100
    buf = BytesIO()
    w = wave.open(buf, "wb")
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(rate)
    frames = bytearray()
    for _ in range(repeats):
        for i in range(int(rate * 0.6)):
            freq = 880 if (i // (rate // 6)) % 2 == 0 else 660
            val = int(32767 * 0.4 * math.sin(2 * math.pi * freq * i / rate))
            frames += struct.pack("<h", val)
        # short silent gap between repeats
        frames += struct.pack("<h", 0) * int(rate * 0.2)
    w.writeframes(frames)
    w.close()
    return "data:audio/wav;base64," + base64.b64encode(buf.getvalue()).decode()


ALARM_URI = alarm_sound_data_uri()


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


def fire_meme_and_sound(attack_count):
    """Show a war meme + play the alarm when the attack count grows.

    Debounced: once a meme is showing, a newer red alert does NOT replace it
    until MEME_HOLD_SECONDS have passed, so a burst lets the current one finish.
    """
    ss = st.session_state
    prev = ss.get("attack_count_seen", None)
    now = time.time()

    # First run just records the count; don't blast a meme for pre-existing rows.
    if prev is None:
        ss["attack_count_seen"] = attack_count
        return

    memes = load_meme_uris()

    # Memes come only from the memes/ folder. Nothing to show if it's empty.
    if not memes:
        return

    new_attacks = attack_count > prev
    ss["attack_count_seen"] = attack_count

    holding = now - ss.get("meme_started_at", 0) < MEME_HOLD_SECONDS
    if new_attacks and not holding:
        ss["meme_started_at"] = now
        ss["meme_index"] = (ss.get("meme_index", -1) + 1) % len(memes)
        ss["play_sound"] = True

    # While within the hold window: tint the whole screen red and show the meme
    # centered, with "WE'RE UNDER ATTACK!!" on its left and right.
    if now - ss.get("meme_started_at", 0) < MEME_HOLD_SECONDS:
        img = memes[ss.get("meme_index", 0) % len(memes)]
        cry = ('<div style="font-size:40px; font-weight:900; color:#ff2222; '
               'line-height:1.1; text-shadow:0 0 12px rgba(255,0,0,0.8); '
               'white-space:nowrap;">WE\'RE UNDER<br>ATTACK!!</div>')
        st.markdown(
            f"""
            <style>
            @keyframes redPulse {{
              0%,100% {{ background: rgba(200,0,0,0.10); }}
              50%     {{ background: rgba(255,0,0,0.28); }}
            }}
            @keyframes popIn {{
              from {{ transform: translate(-50%, -50%) scale(0.6); opacity: 0; }}
              to   {{ transform: translate(-50%, -50%) scale(1);   opacity: 1; }}
            }}
            </style>
            <!-- full-screen red tint -->
            <div style="position:fixed; inset:0; z-index:9998; pointer-events:none;
                        animation: redPulse 0.8s infinite;"></div>
            <!-- centered meme with cries on both sides -->
            <div style="position:fixed; top:50%; left:50%; z-index:9999;
                        transform:translate(-50%,-50%); pointer-events:none;
                        display:flex; align-items:center; gap:32px;
                        animation: popIn 0.35s ease-out;">
              {cry}
              <img src="{img}" style="width:340px; height:340px; object-fit:cover;
                        border:6px solid #ff1111; border-radius:14px;
                        box-shadow:0 0 50px rgba(255,0,0,0.9);">
              {cry}
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Play the alarm once, right after a new meme fires.
    if ss.pop("play_sound", False):
        st.markdown(
            f'<audio autoplay><source src="{ALARM_URI}" type="audio/wav"></audio>',
            unsafe_allow_html=True,
        )


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

    # War meme + alarm when a new attack appears (debounced so bursts don't flicker).
    fire_meme_and_sound(len(attacks))

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
