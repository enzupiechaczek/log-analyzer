# Failed-Login Log Analyzer

A lightweight Python tool that parses SSH authentication logs and flags IP addresses showing signs of brute-force login attempts, a common early indicator of an active attack against a server.

## What It Does

- Parses log files for failed SSH login attempts (`Failed password for ...` lines)
- Counts failed attempts per source IP and per targeted username
- Flags any IP exceeding a configurable threshold (default: 3 failed attempts)
- Outputs a clear summary report with remediation recommendations

## Why I Built This

While working on penetration testing labs (SMB, SQL injection, Redis enumeration), I wanted to build something from the defensive side too — a simple tool that mirrors what a SOC analyst or IT team might use to spot brute-force activity in real server logs, combining my interest in security with practical Python automation.

## Example Output

```
=== Failed Login Analysis Report ===
Generated: 2026-07-22T01:01:51

Top targeted usernames:
  root            5 attempts
  admin           2 attempts
  test            1 attempts

Suspicious IPs (>= 3 failed attempts):
  203.0.113.9     4 failed attempts  -> Recommend firewall block / rate-limit review
  192.168.1.50    3 failed attempts  -> Recommend firewall block / rate-limit review
```

## Usage

```bash
python log_analyzer.py sample_auth.log
```

Run it against any real SSH auth log (e.g., `/var/log/auth.log` on a Linux system) or use the included `sample_auth.log` for a quick demo.

## Possible Future Improvements

- Add automatic IP geolocation lookup for flagged addresses
- Export results to CSV/JSON for integration with a SIEM
- Add a configurable time-window (e.g., flag only attempts within the last hour)
- Extend to parse other log formats (Apache, Nginx, Windows Event Logs)

## Skills Demonstrated

Python scripting, regex pattern matching, log parsing, brute-force attack detection, basic security automation.
