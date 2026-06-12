# Version 1.1 -- please review changelog.md for more details

from collections import defaultdict, deque
from datetime import datetime
import json
import logging
import os
import re
import time

# --- CONFIGURATION ---
LOG_FILE_PATH = "auth.log"
WINDOW_SIZE = 60  # Time window in seconds
THRESHOLD = 3  # Max failures allowed before alerting
ALERT_THROTTLE_PERIOD = 300  # Suppress alerts for the same IP for 5 minutes

# Structured logging setup
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)

# Enhanced regex to capture log timestamp along with the IP
# Works for standard OpenSSH logs: "Dec 10 14:32:10 host sshd[123]: Failed password for invalid user..."
LOG_PATTERN = r"^(?P<timestamp>\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b).*Failed password \
    for .* from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

# State tracking
failed_attempts = defaultdict(deque)
last_alerted = {}  # { ip: timestamp_of_last_alert }


def parse_log_line(line):
    """Extracts timestamp and IP.

    Returns a tuple (epoch_time, ip) or (None, None).
    """
    match = re.search(LOG_PATTERN, line)
    if not match:
        return None, None

    ip = match.group("ip")
    raw_time = match.group("timestamp")

    try:
        # Convert syslog timestamp to epoch. Assumes current year since syslog usually omits it.
        current_year = datetime.now().year
        parsed_dt = datetime.strptime(f"{current_year} {raw_time}", "%Y %b %d %H:%M:%S")
        return parsed_dt.timestamp(), ip
    except ValueError:
        # Fall back to current time if parsing fails
        return time.time(), ip


def correlation_engine(event_time, ip):
    """Processes failed events using log-centric sliding windows and throttles alerts."""
    timestamps = failed_attempts[ip]

    # Record the event timestamp from the log file
    timestamps.append(event_time)

    # Evict logs outside the sliding window relative to the *event time*
    while timestamps and timestamps[0] < event_time - WINDOW_SIZE:
        timestamps.popleft()

    # Threshold evaluation
    if len(timestamps) >= THRESHOLD:
        # Check alert throttling state
        now = time.time()
        if (
            ip not in last_alerted
            or (now - last_alerted[ip]) > ALERT_THROTTLE_PERIOD
        ):
            trigger_alert(ip, len(timestamps), event_time)
            last_alerted[ip] = now


def trigger_alert(ip, count, event_time):
    """Outputs a structured JSON alert, ready for SIEM ingestion or dashboards."""
    alert_time = datetime.fromtimestamp(event_time).strftime("%Y-%m-%d %H:%M:%S")

    alert_payload = {
        "event_type": "security_alert",
        "rule_name": "Brute Force Detected",
        "severity": "HIGH",
        "target_ip": ip,
        "incident_count": count,
        "window_size_seconds": WINDOW_SIZE,
        "detected_at": alert_time,
    }

    # Output as structured JSON string for easy log forwarding
    print(json.dumps(alert_payload, indent=2))


def watch_log():
    """Tails the log file, maintaining pointers across rotations where possible."""
    logging.info(f"Mini SIEM engine online. Monitoring {LOG_FILE_PATH}")

    if not os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, "w") as f:
            f.write("")

    with open(LOG_FILE_PATH, "r") as f:
        # Fast-forward to the end of the file on startup
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            event_time, ip = parse_log_line(line)
            if ip and event_time:
                correlation_engine(event_time, ip)


if __name__ == "__main__":
    try:
        watch_log()
    except KeyboardInterrupt:
        logging.info("Shutting down Mini SIEM engine.")

