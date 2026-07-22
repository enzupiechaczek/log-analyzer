"""
Simple Failed-Login Log Analyzer
Author: Enzu Piechaczek

Parses a Linux auth.log-style file (or any log with similar SSH failed-login
lines) and flags IP addresses with repeated failed login attempts,
a common early indicator of brute-force attacks.

Usage:
    python log_analyzer.py sample_auth.log
"""

import re
import sys
from collections import Counter
from datetime import datetime

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

THRESHOLD = 3  # flag IPs with 3+ failed attempts


def parse_log(filepath):
    ip_counter = Counter()
    user_counter = Counter()

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ip_counter[match.group("ip")] += 1
                user_counter[match.group("user")] += 1

    return ip_counter, user_counter


def report(ip_counter, user_counter):
    print("=== Failed Login Analysis Report ===")
    print(f"Generated: {datetime.now().isoformat()}\n")

    print("Top targeted usernames:")
    for user, count in user_counter.most_common(5):
        print(f"  {user:<15} {count} attempts")

    print("\nSuspicious IPs (>= {} failed attempts):".format(THRESHOLD))
    flagged = [(ip, c) for ip, c in ip_counter.items() if c >= THRESHOLD]
    if not flagged:
        print("  No IPs met the brute-force threshold.")
    else:
        for ip, count in sorted(flagged, key=lambda x: -x[1]):
            print(f"  {ip:<15} {count} failed attempts  -> Recommend firewall block / rate-limit review")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python log_analyzer.py <logfile>")
        sys.exit(1)

    ip_counts, user_counts = parse_log(sys.argv[1])
    report(ip_counts, user_counts)
