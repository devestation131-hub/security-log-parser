# 🔍 Security Log Parser & Alert Engine
**Language:** Python 3 | **Author:** Zachari Higgins

Parses syslog, Windows Event Log (CSV export), and Apache/Nginx access logs. Runs pattern-based and behavioral detection rules to generate prioritized security alerts.

## Features
- Multi-format: syslog, Windows Event CSV, Apache/Nginx
- Detects brute force, privilege escalation, account lockout, new user creation, suspicious processes, port scanning
- Color-coded severity output (CRITICAL / HIGH / MEDIUM / LOW)
- Configurable thresholds and time windows
- Optional log file output

## Usage
```bash
python log_parser.py --file /var/log/auth.log --type syslog
python log_parser.py --file events.csv --type windows --output alerts.log
python log_parser.py --file access.log --type apache --threshold 10
```

## Ethical Use
This tool is intended for authorized security monitoring only.