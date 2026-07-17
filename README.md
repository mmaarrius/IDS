# Python Mini IDS

## What it detects

| Detector         | Type      | What it catches                                                 |
|------------------|-----------|-----------------------------------------------------------------|
| `arp_spoofing`   | signature | An IP (e.g. the gateway) suddenly appearing with a new MAC      |
| `port_scan`      | signature | One IP touching ≥15 distinct ports within 5 seconds            |
| `syn_flood`      | signature | High-rate SYN packets on a flow                                 |
| `dangerous_port` | signature | Connections to insecure ports (21 FTP, 23 Telnet)             |
| `lof`            | anomaly   | An unusual combination of features vs. normal traffic          |
| `zscore`         | anomaly   | A single feature far above/below the normal-traffic average    |
          |

## Usage

### 1. Start the IDS

```bash
# clear old alerts so the numbers stay clean
rm -f alerts.csv ids_alerts.log

sudo ./venv/bin/python src.py --baseline-pcap baseline.pcap
```

### 2. Start the dashboard (another terminal)

```bash
./venv/bin/python -m streamlit run visualizer.py
```

It opens in the browser and auto-refreshes every 3 seconds. It starts empty —
that's normal until alerts appear.

### 3. Test detection (another terminal)

**ARP spoofing** — use your gateway's IP:

```bash
sudo ./venv/bin/python arp_attack_test.py --gateway 10.41.0.1
```

It poisons only this machine's ARP cache and restores it on Ctrl-C. Within a few
seconds the red "ARP SPOOFING DETECTED" banner appears in the dashboard.

**Port scan** — start the IDS on `lo` and scan localhost, so the traffic is
guaranteed to pass through the sniffer:

```bash
# IDS terminal:
sudo ./venv/bin/python src.py --baseline-pcap baseline.pcap --interface lo
# another terminal:
nmap -p 1-100 localhost
```

## Results

Alerts go to two files:
- **`ids_alerts.log`** — one JSON alert per line, human-readable
- **`alerts.csv`** — the same data, for the dashboard / pandas / Excel

Both are append-only across runs. Delete them before a fresh run if you want
clean numbers.

## Regenerating the baseline

`baseline.pcap` is a capture of normal traffic. To make a new one (~2 minutes of
ordinary browsing while it runs):

```bash
sudo tcpdump -i wlp1s0 -w baseline.pcap -n 'tcp' -G 120 -W 1
```

The more representative the baseline is of your normal traffic, the fewer false
alarms the anomaly detection produces.

## Tuning

- **Port scan threshold** — `PORT_SCAN_THRESHOLD` and `PORT_SCAN_WINDOW` in
  `detection_system.py`. Lower the threshold to catch stealthier scans.
- **Anomaly sensitivity** — `contamination` in `detection_system.py`
  (default 0.01). Higher = more anomaly alerts.
