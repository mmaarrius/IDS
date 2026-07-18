"""
Port scan test — for validating YOUR OWN IDS on YOUR OWN network only.

Sends a TCP SYN to many distinct ports on a target machine in a short window.
An IDS sniffing the network sees one source touch many distinct destination
ports in a few seconds and should fire a port_scan alert.

"""

import argparse
import time
from scapy.all import IP, TCP, sr1, RandShort, conf


def main():
    parser = argparse.ArgumentParser(
        description="TCP SYN port scan test against a chosen host on your own network")
    parser.add_argument("--target", required=True,
                        help="IP of the machine to scan (the other laptop "
                             "running the IDS)")
    parser.add_argument("--start-port", type=int, default=1,
                        help="first port to probe (default 1)")
    parser.add_argument("--end-port", type=int, default=100,
                        help="last port to probe (default 100)")
    parser.add_argument("--iface", default=None,
                        help="interface to use (default: system's default route)")
    parser.add_argument("--delay", type=float, default=0.02,
                        help="seconds to wait between probes (default 0.02). "
                             "Keep the whole sweep inside the detector's window "
                             "so the distinct-port count crosses the threshold.")
    args = parser.parse_args()

    # Auto-detect interface from the default route when unspecified.
    iface = args.iface or conf.route.route("0.0.0.0")[0]

    ports = range(args.start_port, args.end_port + 1)
    print(f"Interface: {iface}")
    print(f"Target: {args.target}")
    print(f"Scanning ports {args.start_port}-{args.end_port} "
          f"({len(ports)} ports) with {args.delay}s between probes")

    open_ports = []
    try:
        for dport in ports:
            # SYN-only probe. A random high source port per packet mimics a real
            # scanner and keeps each probe on its own ephemeral flow.
            # sr1 sends one packet and waits for a single reply.
            pkt = IP(dst=args.target) / TCP(sport=RandShort(), dport=dport, flags="S")
            resp = sr1(pkt, timeout=1, iface=iface, verbose=0)

            if resp is not None and resp.haslayer(TCP):
                # SYN-ACK (flags == 0x12) means the port is open. We do NOT send
                # the final ACK, so no full connection is ever established.
                if int(resp[TCP].flags) == 0x12:
                    open_ports.append(dport)
                    print(f"  port {dport}: OPEN")

            time.sleep(args.delay)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        if open_ports:
            print(f"Open ports found: {open_ports}")
        else:
            print("No open ports found (the IDS should still have alerted on "
                  "the scan itself).")
        print("Done.")


if __name__ == "__main__":
    main()