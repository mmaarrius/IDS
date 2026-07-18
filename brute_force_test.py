"""
Brute-force detection test
    ./venv/bin/python bruteforce_test.py --target 192.168.43.50 --port 22
"""
import argparse
import socket
import time


def main():
    parser = argparse.ArgumentParser(
        description="TCP connection-rate test against a chosen host on your own network")
    parser.add_argument("--target", required=True,
                        help="IP of the machine running the IDS you're testing")
    parser.add_argument("--port", type=int, default=22,
                        help="destination port to hit (default 22/SSH)")
    parser.add_argument("--count", type=int, default=25,
                        help="number of connection attempts (default 25, "
                             "should exceed your BRUTEFORCE_THRESHOLD)")
    parser.add_argument("--interval", type=float, default=0.2,
                        help="seconds between attempts (default 0.2, i.e. 5/sec)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="per-connection socket timeout in seconds")
    args = parser.parse_args()

    print(f"Target: {args.target}:{args.port}")
    print(f"Sending {args.count} connection attempts, {args.interval}s apart "
          f"(~{1/args.interval:.1f}/sec)")
    print("No credentials are sent — this only opens/closes TCP connections.\n")

    successes = 0
    failures = 0

    try:
        for i in range(args.count):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(args.timeout)
            try:
                s.connect((args.target, args.port))
                successes += 1
                print(f"  attempt {i + 1}/{args.count}: connected")
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                failures += 1
                print(f"  attempt {i + 1}/{args.count}: failed ({e})")
            finally:
                s.close()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nInterrupted.")

    print(f"\nDone. {successes} connected, {failures} failed/refused.")
    print("Check your IDS output for a 'bruteforce' alert on this source IP.")


if __name__ == "__main__":
    main()