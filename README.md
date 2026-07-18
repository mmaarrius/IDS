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

The interface is auto-detected from your default route. If you switched networks
since the last capture, retrain the baseline first (see "Retraining the baseline
on a new network" below), or the anomaly detectors will be very noisy.

### 2. Start the dashboard (another terminal)

```bash
./venv/bin/python -m streamlit run visualizer.py
```

It opens in the browser and auto-refreshes every 3 seconds. It starts empty —
that's normal until alerts appear.

### 3. Test detection (another terminal)

**ARP spoofing** — use your gateway's IP:

```bash
sudo ./venv/bin/python3 arp_attack_test.py --target <IP-LAPTOP_TARGET>
```

It poisons only this machine's ARP cache and restores it on Ctrl-C. Within a few
seconds the red "ARP SPOOFING DETECTED" banner appears in the dashboard.

**Port scan** — sends a TCP SYN to many distinct ports on a target in a short
window. Start the IDS on `lo` and scan localhost, so the traffic is guaranteed
to pass through the sniffer:

```bash
# IDS terminal:
sudo ./venv/bin/python src.py --baseline-pcap baseline.pcap --interface lo
# another terminal:
sudo ./venv/bin/python port_scanning_test.py --target 127.0.0.1 --iface lo --start-port 1 --end-port 100
```

Or against another laptop on the same network, same as the ARP test:

```bash
sudo ./venv/bin/python port_scanning_test.py --target <IP-LAPTOP_TARGET>
```

It never completes the TCP handshake (SYN only, no final ACK), so no real
connection is ever made. Within a few seconds the "PORT SCAN DETECTED" alert
appears in the dashboard.

## Results

Alerts go to two files:
- **`ids_alerts.log`** — one JSON alert per line, human-readable
- **`alerts.csv`** — the same data, for the dashboard / pandas / Excel

Both are append-only across runs. Delete them before a fresh run if you want
clean numbers.

## Retraining the baseline on a new network

**The baseline is tied to the network it was captured on.** `baseline.pcap` is a
recording of *your* normal traffic, and the anomaly detectors (LOF, z-score)
compare live traffic against it. Move to a different network (new Wi-Fi, cable,
phone hotspot) and the old baseline no longer matches — the anomaly detectors
will fire on almost everything, because their idea of "normal" is from somewhere
else. Signature detectors (ARP, port scan, SYN flood) are not affected; they
don't use the baseline.

So whenever you change network, recapture the baseline before running.

### 1. Find your current interface

```bash
ip route get 1.1.1.1
```

The word after `dev` is your active interface (e.g. `wlp1s0` for Wi-Fi,
`enxXXXX` for a USB/cable adapter).

### 2. Capture ~2 minutes of normal traffic

Run this, then browse normally (open several sites, let background apps talk) so
the capture reflects a realistic mix. It stops itself after 120 seconds.

```bash
sudo tcpdump -i <interface> -w baseline.pcap -n 'tcp' -G 120 -W 1
```

The longer and more varied the capture, the wider the model's idea of "normal",
and the fewer false alarms you get. A too-short capture makes LOF flag any
activity it didn't happen to see.

### 3. Run the IDS on the new baseline

```bash
rm -f alerts.csv ids_alerts.log     # clear old alerts for clean numbers
sudo ./venv/bin/python src.py --baseline-pcap baseline.pcap
```

The interface is auto-detected from your default route, so no `--interface` flag
is needed unless you want a specific one (e.g. `--interface lo` for local tests).

## Tuning

- **Port scan threshold** — `PORT_SCAN_THRESHOLD` and `PORT_SCAN_WINDOW` in
  `detection_system.py`. Lower the threshold to catch stealthier scans.
- **Anomaly sensitivity** — `contamination` in `detection_system.py`
  (default 0.01). Higher = more anomaly alerts.
