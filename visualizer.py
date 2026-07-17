import os
import streamlit as st
import pandas as pd


st.title("Python Mini IDS Dashboard")


# Load CSVs
logs = pd.read_csv("simulated_auth_logs.csv", parse_dates=['timestamp'])
alerts = pd.read_csv("alerts.csv", parse_dates=['timestamp']) if os.path.exists("alerts.csv") else pd.DataFrame()


# Display Logs
st.subheader("Login Logs")
st.dataframe(logs)


# Display Alerts
st.subheader("Alerts")
if not alerts.empty:
    st.dataframe(alerts)
else:
    st.write("No alerts detected yet.")


# Visualize Failed Logins
st.subheader("Failed Logins by User")
failed_logins = logs[logs['status'] == 'fail'].groupby('username').size()
st.bar_chart(failed_logins)


# Top IPs with Failed Logins
st.subheader("Top 10 IPs by Failed Logins")
top_ips = logs[logs['status'] == 'fail'].groupby('ip_address').size().sort_values(ascending=False).head(10)
st.bar_chart(top_ips)