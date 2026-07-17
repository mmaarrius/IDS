
Skip to content
DEV Community
Powered by Algolia
Log in
Create account
Cover image for First few steps to 6 Figures: A Beginner’s Guide to Building a Real-Time Mini IDS Using Python
UP Mindanao SPARCS profile image
Joshua Yacob Papica
Joshua Yacob Papica for UP Mindanao SPARCS

Posted on 22 feb.
First few steps to 6 Figures: A Beginner’s Guide to Building a Real-Time Mini IDS Using Python
#tutorial
#python
#cybersecurity
#beginners

This article was co-authored by @reydocs.
Introduction

If you have ever taken a look at network traffic logs, you’ll notice constant connection attempts from users. While some come from legitimate ones, others are clearly suspicious due to repeated failures.

This is where Intrusion detection systems, or IDS, come in. An IDS monitors network activity and identifies suspicious behavior such as repeated failed login attempts or unusual access patterns, allowing organizations to take action as soon as unusual activity appears.

In this article, you will learn how to create your own hybrid IDS consisting of different IDS types while only using Python. By the end, you’ll even see how to visualize your results with an interactive dashboard.
Table of Contents

    Types of IDS
    Project Overview
    Tools and Technologies Used
    Setting Up Your Environment
    Packet Capture Engine
    Traffic Analysis Engine
    Detection Engine
    Alert System
    Simulating the IDS
    Combining It All Together
    Visualizing the data using Streamlit
    To sum it up
    Potential Improvements
    Final Thoughts

TYPES OF IDS

Before we go into creating our own IDS, we must first understand the different types of IDS and what they do.

    Network IDS(NIDS)

NIDS is a security tool that is used to monitor your network traffic for suspicious activity by performing Traffic Monitoring, Analysis, and Alerts.

    Host IDS(HIDS)

HIDS monitors system logs for signs of suspicious activity to detect unusual behaviours associated with either human users or applications.

    Signature IDS

Signature-based IDS is a system either on the network or host and identifies threats by comparing the system activity to a database of known attack patterns or signatures to detect unusual behavior.

    Anomaly IDS

Anomaly-based IDS identifies unusual behavior by learning patterns of normal activity and flagging deviations from that baseline.
PROJECT OVERVIEW

This Mini IDS tutorial was built to demonstrate how intrusion detection works at a fundamental level and to create a simplified system that monitors authentication activity, detects unusual behavior, and generates alerts.
TOOLS AND TECHNOLOGIES USED

This project relies entirely on Python and its ecosystem of libraries, including:

    Scapy - Captures and inspects network packets in real time.
    Scikit-learn - Provides the Isolation Forest Algorithm for detecting anomalies in network traffic
    python-nmap - Scans and maps network hosts and open ports to identify potential threats.
    NumPy - Performs numerical operations and processes
    Logging - Python’s built-in-module for generating alerts and recording suspicious activity
    Queue & Threading - Enables efficient handling of multiple packets simultaneously
    Pandas - Reads CSV files and organizes traffic for data analysis
    Streamlit - Builds an interactive dashboard to visualize network activity and detected threats.

Having introduced the technologies that power our IDS, let’s take a look at how they fit together in the system’s overall architecture, from packet capture to visualization.

Our mini IDS captures network packets and records them as logs. Then, they are analyzed by the detection engine using signature rules and anomaly detection to identify suspicious activity. When a threat is found, the alert system generates warnings, which are then displayed on a Streamlit dashboard for visualization
SETTING UP YOUR ENVIRONMENT

Before building the core modules, make sure you have an IDE that supports Python 3.10 or later. It’s recommended to use a virtual environment (venv) to keep your project dependencies isolated. You can create one with:

python -m venv venv

Then activate it by typing the following:

source venv/bin/activate  # for macOS/Linux

venv\Scripts\activate.bat # for Windows(Command Prompt)

venv\Scripts\Activate.ps1 # For Windows (PowerShell)

Then Install the following:

pip install scapy
pip install python-nmap
pip install numpy
pip install scikit-learn
pip install pandas

SETTING UP STREAMLIT

Since we will be using Streamlit to visualize the data given by our mini IDS, you should also learn how to install your Streamlit.

pip install streamlit

After installing, you can verify its installation by running this command:

streamlit hello

After installing and setting up everything, we can now proceed to building the core components.
LET’S BEGIN!

Since our IDS is a hybrid system of signature and anomaly-based IDS, it will comprise of four main components:

    A packet capture system
    A traffic analysis module
    A detection engine
    An alert system

Important Note: Network interface names differ depending on the operating system. Before running the IDS, ensure that the interface parameter in the code matches your system’s active network interface. Refer to the README in the repository for guidance.
THE PACKET CAPTURE ENGINE

We’ll start with the packet capture engine and for this, we will use Scapy. Scapy is a networking library that allows users to perform network-related tasks using Python.

We’ll define our PacketEngine class that will serve as the basis for our IDS.

from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue
#PACKET CAPTURE ENGINE
class packetCapture:
    def __init__(self): #initializes the class
        #stores captured packets
        self.packet_queue= queue.Queue()
        #controls when the packet capture should stop
        self.stop_capture= threading.Event()

    #acts as a handler for each captured packets
    #checks if packets have IP or TCP layers
    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="eth0"):
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _: self.stop_capture.is_set())
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()
    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()

Let’s walk through the code to understand what each line of code does and its functions.

The __init__ method initializes the class by creating a queue.Queue where the captured packets are stored and a threading.Event to control whether the capturing of packets should be stopped. The packet_callback serves as a handler for the captured packets and also checks if the captured packets have both IP or TCP layers, and if they do, they are added to the queue for further processing.

The start_capture method starts capturing packets on a specified interface, with eth0 as the default interface since it captures packets from your Ethernet interface.

The function runs a separate thread to execute Scapy’s sniff function to continuously capture packets on the interface. The stop_filter parameter ensures that capturing stops when stop_capture is triggered.

The stop method stops the capture by triggering the stop_capture event and waits for the thread to finish, ensuring smooth termination. This design allows for real-time packet monitoring and capturing without blocking the main thread.
THE TRAFFIC ANALYSIS ENGINE

We will now build the Traffic Analysis Engine. This module will process the captured packets and extract important features.

#TRAFFIC ANALYSIS MODULE  
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue

class trafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda:{
            'packet_count' : 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time  

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        # Using max() to ensure duration is never strictly 0, avoiding ZeroDivisionError
        duration = max(stats['last_time'] - stats['start_time'], 0.0001)

        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': stats['packet_count'] / duration,
            'byte_rate': stats['byte_count'] / duration,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }

In this module, we defined the trafficAnalyzer class to analyze the network traffic. We can track connection flows here and calculate statistics for the packets in real-time. We used the defaultdict data structure in Python for managing connections and data flow statistics by organizing them into different unique flows.

The __init__ method initializes two things: the connections and flow_stats. The connections attribute stores the list of related packets, while flow_stats stores the statistics for each flow, including packet_count, byte_count, start_time, and last_time.

The analyze_packet method analyzes and processes each packet. If the packets contain IP or TCP layers, it extracts the source IP and destination IP ports, creating a flow_key to identify the flow. It updates the statistics by incrementing the packet count, adding the packet size to the byte count, and adjusting the start time and last time of the flow.

The extract_features method computes the details of the captured packets. These include the packet size, flow duration, packet rate, byte rate, TCP flags, and the TCP window size. These features are useful in identifying patterns and malicious behaviors in the network traffic.
THE DETECTION ENGINE

Now, we will build the Detection Engine that will implement the signature and anomaly based detection mechanisms.

from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError # Added this import
import numpy as np

class detectionEngine:
    def __init__(self):
        # Corrected the typo here as well
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data= []

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and # SYN flag
                    features['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and
                    features['packet_rate'] > 50
                )
            }
        }

    def train_anomaly_detector(self, normal_traffic_data):
        self.anomaly_detector.fit(normal_traffic_data)

    def detect_threats(self, features):
        threats = []
        # Signature detection always runs
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({'type': 'signature', 'rule': rule_name, 'confidence': 1.0})

        feature_vector = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]])

        # This block prevents the NotFittedError from crashing the app
        try:
            from sklearn.exceptions import NotFittedError
            anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
            if anomaly_score < -0.5:
                threats.append({
                    'type': 'anomaly',
                    'score': anomaly_score,
                    'confidence': min(1.0, abs(anomaly_score))
                })
        except (NotFittedError, AttributeError):
            pass # Skip anomaly check if model isn't ready

        return threats

This module defines a hybrid system, utilizing signature and anomaly-based detection methods. We used the IsolationForest model to detect anomalies and also used its pre-defined rules and functions to detect and identify anomalous patterns.

In this code block, the train_anomaly_detector method is used to train the IsolationForest model using a dataset of normal traffic measures. This ensures that the model knows what the “normal” traffic looks like beforehand to differentiate different traffic patterns.

The detect_threats method evaluates the network traffic features for potential threats using two approaches:

    Signature-based Detection: It iteratively goes through the pre-defined rules and applies each rule to the traffic. If the traffic matches a rule, the system flags it as a signature-based threat and records it with high confidence.
    Anomaly-based Detection: It processes the feature vector (packet_size, packet_rate, and byte_rate) through the IsolationForest model and calculates an anomaly score. If the score indicates a threat, the engine triggers it as an anomaly and produces an anomaly score that reflects the threat’s severity.

Finally, we return the aggregate list of identified threats with their respective annotations or tags (either signature or anomaly), the score that triggered the anomaly, and its confidence score showing the severity and whether it is a threat.
THE ALERT SYSTEM

This module will be responsible for processing and organizing the logs in a more structured manner.

import logging
import json
from datetime import datetime
import pandas as pd
import os

class alertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))

        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )
        alert_df = pd.DataFrame([alert])
        if os.path.exists("alerts.csv"):
            alert_df.to_csv("alerts.csv", mode='a', header=False, index=False)
        else:
            alert_df.to_csv("alerts.csv", index=False)

The __init__ method initializes a logger named IDS_Alerts with INFO logging to catch alert information. It writes logs to a specific file ids_alerts.log. The FileHandler directs the captured logs to the file, and the Formatter formats them.

The generate_alert method is responsible for creating structured entries. Each alert shows key information such as the timestamp of detection, the type of threat, the source and destination IPs involved, its confidence level, and additional threat-specific information. These alerts are logged as WARNING level messages in JSON format.

If the confidence level is high (higher than 0.8), the alert is escalated and logged as a CRITICAL level message. This method is extensible, allowing for additional notification mechanisms, such as sending the alerts via email, etc.
SIMULATING THE IDS

Now that you have built the IDS, we will now try to run a simulation for it. We will need a file to train our Isolation Forest model to determine the normal and abnormal patterns in the packets and another file to generate the log attempts.

import numpy as np
from detectionEngine import detectionEngine
from alertSystem import alertSystem

# Initialize engine
engine = detectionEngine()
alerts = alertSystem(log_file="test_alerts.log")

# Train the anomaly detector with mock normal traffic
normal_traffic = np.array([
    [60, 10, 600],   # packet_size, packet_rate, byte_rate
    [70, 12, 840],
    [65, 8, 520]
])
engine.train_anomaly_detector(normal_traffic)

# Example features that will trigger signature-based alert
features = {
    'packet_size': 60,
    'packet_rate': 120,  # > 100 triggers SYN flood rule
    'byte_rate': 720,
    'tcp_flags': 2  # SYN flag
}

# Detect threats
threats = engine.detect_threats(features)

# Generate alerts
for threat in threats:
    packet_info = {
        'source_ip': '192.168.1.5',
        'destination_ip': '192.168.1.3'
    }
    alerts.generate_alert(threat, packet_info)

print("Alerts generated. Check test_alerts.log")

In this code, we created a test_alerts script to train our model to determine which traffic is normal or abnormal. It creates a "normal" baseline and feeds a "malicious scenario" into the engine. This allows us to verify whether the detection logic works without having to risk your machine to a real cyber attack.

import pandas as pd
import random
from datetime import datetime, timedelta

# Config
num_entries = 1000
users = ['alice', 'bob', 'charlie', 'dave']
ip_pool = ['192.168.1.' + str(i) for i in range(2, 20)] + ['10.0.0.' + str(i) for i in range(2, 20)]
status_options = ['success', 'fail']

# Generate logs
logs = []
start_time = datetime.now() - timedelta(days=1)

for _ in range(num_entries):
    timestamp = start_time + timedelta(seconds=random.randint(0, 86400))
    user = random.choice(users)
    ip = random.choice(ip_pool)
    status = random.choices(status_options, weights=[0.8,0.2])[0]
    logs.append([timestamp, user, ip, status])

# Create CSV
df_logs = pd.DataFrame(logs, columns=['timestamp', 'username', 'ip_address', 'status'])
df_logs.to_csv('simulated_auth_logs.csv', index=False)

print("simulated_auth_logs.csv created!")

In this code, we created a LogAttempts script to generate “mock” data for the system. It creates a history of “fake” user logins and generates 1000 random login attempts using a list of fake users and random IP addresses. This ensures that the dashboard will not look empty, and it needs to be run at least once before running the miniIntrusionDetectionSystem and dashboard.py.
COMBINING IT ALL TOGETHER

Now that we have our 4 modules, we can now start putting them all together to create a functional IDS solution.

from alertSystem import alertSystem
from detectionEngine import detectionEngine
from packetCapture import packetCapture
from trafficAnalyzer import trafficAnalyzer
import queue
from scapy.all import IP, TCP
import pandas as pd
import numpy as np  # needed for feature arrays

class intrusionDetectionSystem:
    def __init__(self, interface="Wi-Fi"):
        self.packet_capture = packetCapture()
        self.traffic_analyzer= trafficAnalyzer()
        self.detection_engine = detectionEngine()
        self.alert_system = alertSystem()

        self.interface = interface

        # --------------------------
        # Train anomaly detector from CSV
        # --------------------------
        try:
            df = pd.read_csv("simulated_auth_logs.csv")
            df['packet_size'] = df['status'].apply(lambda x: 1 if x == 'fail' else 0)
            packet_counts = df.groupby('ip_address').cumcount() + 1
            df['packet_rate'] = packet_counts
            df['byte_rate'] = packet_counts  # simple placeholder
            training_data = df[['packet_size', 'packet_rate', 'byte_rate']].values
            self.detection_engine.train_anomaly_detector(training_data)
            print("Anomaly detector trained from simulated_auth_logs.csv")
        except FileNotFoundError:
            print("simulated_auth_logs.csv not found. Anomaly detection will not work.")

    def start(self):
        print(f"Starting IDS on Interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        training_samples = []
        is_trained = False # Flag to prevent premature detection
        import time
        start_time = time.time()

        print("Phase 1: Collecting baseline traffic (5 seconds)...")

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    # Check if we are still in the training phase
                    if not is_trained:
                        training_samples.append([
                            features['packet_size'],
                            features['packet_rate'],
                            features['byte_rate']
                        ])

                        # Once we have 5 seconds of data, train the model
                        if time.time() - start_time > 5:
                            print(f"Training model on {len(training_samples)} packets...")
                            self.detection_engine.train_anomaly_detector(training_samples)
                            is_trained = True
                            print("Phase 2: IDS is now ACTIVE.")

                    # Only run detection if the model is ready
                    else:
                        threats = self.detection_engine.detect_threats(features)
                        for threat in threats:
                            packet_info = {
                                'source_ip': packet[IP].src,
                                'destination_ip': packet[IP].dst,
                                'source_port': packet[TCP].sport,
                                'destination_port': packet[TCP].dport
                            }
                            self.alert_system.generate_alert(threat, packet_info)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS.....")
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    ids = intrusionDetectionSystem()
    ids.start()


Here, the intrusionDetectionSystem sets up its core parts: packetCapture for capturing packets on the network interface, trafficAnalyzer for extracting packet features and analyzing them, detectionEngine for identifying threats using both signature and anomaly-based detection methods, and alertSystem for logging and escalating threat alerts. The interface parameter specifies which network interface to monitor, defaulting to the system default (in this case, "Wi-Fi" for Windows and "en0" for Mac).

The start function executes the IDS, beginning monitoring on the specified interface and entering a continuous loop to process incoming packets. For each captured packet, the system uses the trafficAnalyzer to extract features and analyze them for potential threats with the detectionEngine. If threats are detected, detailed alerts are generated through the alertSystem.
VISUALIZING THE DATA USING STREAMLIT

Sample Streamlit Dashboard

Sample Streamlit Dashboard

Optionally, if you want to visualize the logs being detected by your system, you can use Streamlit to do so. We’ll have a quick run through on how to create a simple dashboard for your IDS.

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

In this code, the dashboard connects to the IDS by reading two different files: simulated_auth_logs.csv, which contains the general login history (who logged in, from where, and whether they succeeded or not), and alerts.csv, which loads alerts detected by the detectionEngine.

The tables use st.dataframe() to display the raw logs in a scrollable table. If alerts.csv contains detected threats, they are displayed in the table; otherwise, the table shows a "No alerts detected yet" status message.

The dashboard also uses two graphs to help you spot patterns. You can view failed user logins to identify if a specific account is being targeted and highlight which IP addresses are causing the most trouble, making it easier to identify a potential attacker’s address.

Streamlit is great for visualizing data. If you want to further enhance your understanding about building your own dashboard, you can read this article.
TO SUM IT UP

Creating this mini IDS gives you a hands-on look at how systems can monitor network activity and flag unusual events. You’ve seen how Python and a few key libraries can be combined to build something practical from scratch. While this provides a solid foundation, there is always room to enhance the system further.
POTENTIAL IMPROVEMENTS

While our mini IDS effectively identifies suspicious activity in simulated traffic, there are a few areas where it could be enhanced. For example, adding more refined detection rules could help catch subtle or complex attack patterns. Integrating real-time threat intelligence would allow the system to respond to emerging threats faster. Improving packet processing efficiency could also make the IDS more responsive under high network load.
FINAL THOUGHTS

Congratulations! By completing this project, you’ve taken your first real step into the world of cybersecurity. Keep building, keep experimenting, and remember, every line of code you write brings you closer to that 6‑digit career you’re aiming for.

Github repository:

SPARCS_miniIDS GitHub

Reference:

https://www.freecodecamp.org/news/build-a-real-time-intrusion-detection-system-with-python/
profile
Sentry
Promoted

Sentry blog image
Build, Ship, See It All: MCP Monitoring with Sentry

Built an MCP server? Now see everything it does. Sentry’s MCP Server Monitoring tracks every client, tool, and request so you can fix issues fast and build with confidence.

Read more
Top comments (0)
Subscribe
pic
Code of Conduct • Report abuse
profile
Sentry
Promoted

Sentry image
See why 4M developers consider Sentry, “not bad.”

Fixing code doesn’t have to be the worst part of your day. Learn how Sentry can help.

Learn more
UP Mindanao SPARCS
Tech Leaders. Community Builders.
More from UP Mindanao SPARCS
Software Development 101: A Crash Course in Version Control with Git and Github
#git #github #beginners #tutorial
A Beginner’s Guide to Building a REST API with Express.js, PostgreSQL, and Postman
#beginners #tutorial #learning #node
No Wifi? No Problem: Using ElectricSQL ⚡ to Implement Local-First Syncing
#database #sql #tutorial #webdev
profile
MongoDB
Promoted

MongoDB Atlas image
Scale your AI apps to 125+ cloud regions.

Atlas handles the sharding, backups, and failover while you focus on shipping features. Get a flexible document model and integrated vector search on any cloud provider. Create your free cluster now.

Start Free

#TRAFFIC ANALYSIS MODULE  
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue

class trafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda:{
            'packet_count' : 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time  

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        # Using max() to ensure duration is never strictly 0, avoiding ZeroDivisionError
        duration = max(stats['last_time'] - stats['start_time'], 0.0001)

        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': stats['packet_count'] / duration,
            'byte_rate': stats['byte_count'] / duration,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }
    