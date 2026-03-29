#!/usr/bin/env python3
"""
log_parser.py — Security Log Parser & Alert Engine
Author : Zachari Higgins
Parses syslog, Windows Event Log (CSV), and Apache/Nginx access logs.
Detects anomalies and generates prioritized security alerts.

Usage:
    python log_parser.py --file /var/log/auth.log --type syslog
    python log_parser.py --file events.csv --type windows --output alerts.log
    python log_parser.py --file access.log --type apache --threshold 10
"""

import re, sys, csv, argparse
from datetime import datetime
from collections import defaultdict
from pathlib import Path

RED = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"
CYAN = "\033[96m"; RESET = "\033[0m"; BOLD = "\033[1m"

SEVERITY_COLORS = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}

DETECTION_RULES = {
    "brute_force": {
        "desc": "Brute force / repeated auth failures",
        "severity": "HIGH", "threshold": 5, "window_sec": 60,
    },
    "priv_esc": {
        "desc": "Privilege escalation attempt",
        "severity": "CRITICAL",
        "patterns": [r"sudo.*FAILED", r"su: FAILED", r"pam_unix.*authentication failure.*root",
                     r"EventID.*4672", r"EventID.*4673"],
    },
    "account_lockout": {
        "desc": "Account locked out",
        "severity": "HIGH",
        "patterns": [r"account.*locked", r"EventID.*4740", r"pam_unix.*account.*locked"],
    },
    "new_user": {
        "desc": "New user account created",
        "severity": "MEDIUM",
        "patterns": [r"useradd", r"EventID.*4720", r"net user.*/add"],
    },
    "suspicious_process": {
        "desc": "Suspicious process execution",
        "severity": "HIGH",
        "patterns": [r"nc\s+-[elvp]", r"ncat", r"powershell.*-enc", r"mshta",
                     r"certutil.*-urlcache", r"bitsadmin.*/transfer"],
    },
}

class Alert:
    def __init__(self, rule_name, severity, description, source_line, timestamp=None):
        self.rule_name = rule_name
        self.severity = severity
        self.description = description
        self.source_line = source_line
        self.timestamp = timestamp or datetime.now().isoformat()
    
    def __str__(self):
        color = SEVERITY_COLORS.get(self.severity, RESET)
        return (f"{color}[{self.severity}]{RESET} {self.description}\n"
                f"  Rule: {self.rule_name} | Time: {self.timestamp}\n"
                f"  Source: {self.source_line[:120]}...")

class LogParser:
    def __init__(self, threshold=5, window=60):
        self.alerts = []
        self.failed_logins = defaultdict(list)  # ip -> [timestamps]
        self.port_access = defaultdict(set)      # ip -> {ports}
        self.threshold = threshold
        self.window = window
    
    def parse_file(self, filepath, log_type):
        path = Path(filepath)
        if not path.exists():
            print(f"{RED}[ERROR] File not found: {filepath}{RESET}")
            sys.exit(1)
        
        print(f"{CYAN}[*] Parsing {log_type} log: {filepath}{RESET}")
        
        if log_type == "syslog":
            self._parse_syslog(path)
        elif log_type == "windows":
            self._parse_windows_csv(path)
        elif log_type == "apache":
            self._parse_apache(path)
        else:
            print(f"{RED}[ERROR] Unknown log type: {log_type}{RESET}")
            sys.exit(1)
        
        self._check_brute_force()
        self._check_port_scan()
        return self.alerts
    
    def _parse_syslog(self, path):
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Check pattern-based rules
                for rule_name, rule in DETECTION_RULES.items():
                    if "patterns" in rule:
                        for pattern in rule["patterns"]:
                            if re.search(pattern, line, re.IGNORECASE):
                                self.alerts.append(Alert(
                                    rule_name, rule["severity"], rule["desc"], line
                                ))
                                break
                # Track failed logins for brute force detection
                fail_match = re.search(
                    r"(?:Failed password|authentication failure).*?(?:from\s+|rhost=)([\d.]+)", line, re.IGNORECASE
                )
                if fail_match:
                    ip = fail_match.group(1)
                    self.failed_logins[ip].append(datetime.now())
    
    def _parse_windows_csv(self, path):
        with open(path, "r", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                line = str(row)
                event_id = row.get("EventID", row.get("Event ID", row.get("Id", "")))
                for rule_name, rule in DETECTION_RULES.items():
                    if "patterns" in rule:
                        for pattern in rule["patterns"]:
                            if re.search(pattern, line, re.IGNORECASE):
                                self.alerts.append(Alert(
                                    rule_name, rule["severity"], rule["desc"], line,
                                    timestamp=row.get("TimeCreated", row.get("Date and Time", ""))
                                ))
                                break
                # Track failed logins (EventID 4625)
                if str(event_id) == "4625":
                    ip = row.get("IpAddress", row.get("Source Network Address", "unknown"))
                    self.failed_logins[ip].append(datetime.now())
    
    def _parse_apache(self, path):
        apache_re = re.compile(r'^([\d.]+)\s.*?"(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+).*?"\s+(\d+)\s+(\d+)')
        with open(path, "r", errors="ignore") as f:
            for line in f:
                match = apache_re.match(line)
                if match:
                    ip, uri, status, size = match.groups()
                    # Track unique paths per IP for scan detection
                    self.port_access[ip].add(uri)
                    # Suspicious URI patterns
                    if re.search(r"\.\./|/etc/passwd|/proc/self|cmd\.exe|<script", uri, re.IGNORECASE):
                        self.alerts.append(Alert(
                            "web_attack", "HIGH", f"Suspicious URI from {ip}: {uri}", line
                        ))
    
    def _check_brute_force(self):
        for ip, timestamps in self.failed_logins.items():
            if len(timestamps) >= self.threshold:
                self.alerts.append(Alert(
                    "brute_force", "HIGH",
                    f"Brute force: {len(timestamps)} failed logins from {ip}",
                    f"IP: {ip}, Failures: {len(timestamps)}"
                ))
    
    def _check_port_scan(self):
        for ip, paths in self.port_access.items():
            if len(paths) >= 15:
                self.alerts.append(Alert(
                    "port_scan", "MEDIUM",
                    f"Possible scan: {len(paths)} unique paths from {ip}",
                    f"IP: {ip}, Unique paths: {len(paths)}"
                ))

def main():
    parser = argparse.ArgumentParser(description="Security Log Parser & Alert Engine")
    parser.add_argument("--file", required=True, help="Path to log file")
    parser.add_argument("--type", required=True, choices=["syslog", "windows", "apache"])
    parser.add_argument("--output", help="Write alerts to file")
    parser.add_argument("--threshold", type=int, default=5, help="Brute force threshold (default: 5)")
    args = parser.parse_args()
    
    engine = LogParser(threshold=args.threshold)
    alerts = engine.parse_file(args.file, args.type)
    
    print(f"\n{BOLD}{'='*60}")
    print(f" ALERT SUMMARY — {len(alerts)} alerts detected")
    print(f"{'='*60}{RESET}\n")
    
    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda a: severity_order.get(a.severity, 99))
    
    for alert in alerts:
        print(alert)
        print()
    
    if args.output:
        with open(args.output, "w") as f:
            for alert in alerts:
                f.write(f"[{alert.severity}] {alert.description} | {alert.rule_name} | {alert.timestamp}\n")
        print(f"{GREEN}[+] Alerts written to {args.output}{RESET}")
    
    # Summary stats
    by_sev = defaultdict(int)
    for a in alerts:
        by_sev[a.severity] += 1
    print(f"\n{BOLD}Breakdown:{RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if by_sev[sev]:
            color = SEVERITY_COLORS[sev]
            print(f"  {color}{sev}: {by_sev[sev]}{RESET}")

if __name__ == "__main__":
    main()
