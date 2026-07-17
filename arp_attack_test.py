"""
ARP spoofing SELF-TEST — for validating this machine's own IDS only.

This poisons THIS laptop's ARP cache: it tells this host that the gateway IP
lives at this same host's MAC, so the IDS (sniffing on the same box) sees a
gateway IP suddenly answering from a new MAC and should fire an arp_spoofing
alert. It targets only the loopback of your own setup — the victim IP defaults
to this machine and the "attacker" MAC is this machine's own MAC.

Intended use: your hardware, your network, testing your own detector.
Run in a second terminal while src.py is running. Ctrl-C restores the cache.

    sudo ./venv/bin/python arp_attack_test.py --gateway 10.41.0.1
"""
import argparse
import time
from scapy.all import ARP, Ether, srp, send, get_if_hwaddr, conf


def mac_of(ip, iface):
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, iface=iface, verbose=0,
    )
    for _, rcv in ans:
        return rcv[Ether].src
    return None


def main():
    parser = argparse.ArgumentParser(description="ARP spoofing self-test against this machine")
    parser.add_argument("--gateway", required=True,
                        help="gateway IP whose identity will be spoofed to this host")
    parser.add_argument("--iface", default=conf.iface, help="interface to use")
    parser.add_argument("--count", type=int, default=20,
                        help="number of spoofed replies to send (default 20)")
    args = parser.parse_args()

    victim_ip = conf.route.route(args.gateway)[1]  # this machine's IP on that path
    attacker_mac = get_if_hwaddr(args.iface)       # this machine's own MAC

    print(f"Interface: {args.iface}")
    print(f"Victim (this machine): {victim_ip}")
    print(f"Spoofing gateway {args.gateway} -> claiming it is at {attacker_mac}")

    real_gw_mac = mac_of(args.gateway, args.iface)
    if real_gw_mac is None:
        print("Could not resolve the real gateway MAC; is the gateway IP correct?")
        return

    # Tell the victim: "the gateway is at my MAC." Since victim == attacker here,
    # this poisons only this host's own cache.
    poison = ARP(op=2, pdst=victim_ip, psrc=args.gateway, hwdst=attacker_mac,
                 hwsrc=attacker_mac)
    try:
        for i in range(args.count):
            send(poison, iface=args.iface, verbose=0)
            print(f"  sent spoofed reply {i + 1}/{args.count}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        # Restore: re-announce the gateway's real MAC so the cache heals.
        print("Restoring correct ARP mapping...")
        fix = ARP(op=2, pdst=victim_ip, psrc=args.gateway, hwdst=attacker_mac,
                  hwsrc=real_gw_mac)
        send(fix, count=5, iface=args.iface, verbose=0)
        print("Done.")


if __name__ == "__main__":
    main()
