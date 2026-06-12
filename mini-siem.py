import os
import re
import time
from collections import defaultdict, deque

# --- CONFIGURATION ---
LOG_FILE_PATH = "auth.log"
FAILED_LOGIN_PATTERN = r"Failed password for .* from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
WINDOW_SIZE = 60  # Time window in seconds to track attempts
THRESHOLD = 3     # Maximum allowed failures before alerting

# Tracking dictionary: { ip: deque([timestamp1, timestamp2, ...]) }
failed_attempts = defaultdict(lambda: deque())

def parse_log_line(line):
    """Extracts relevant data from a log line using Regex."""
    match = re.search(FAILED_LOGIN_PATTERN, line)
    if match:
        return match.group("ip")
    return None

def correlation_engine(ip):
    """Checks if the IP has breached the security threshold."""
    current_time = time.time()
    timestamps = failed_attempts[ip]
    
    # Record the current failed attempt
    timestamps.append(current_time)
    
    # Clean up timestamps older than our sliding window (60 seconds)
    while timestamps and timestamps[0] < current_time - WINDOW_SIZE:
        timestamps.popleft()
    
    # Check if threshold is breached
    if len(timestamps) >= THRESHOLD:
        trigger_alert(ip, len(timestamps))

def trigger_alert(ip, count):
    """Handles the alerting mechanism."""
    print("\n[!!!] SECURITY ALERT [!!!]")
    print(f"POSSIBLE BRUTE FORCE DETECTED: IP {ip} failed login {count} times in the last {WINDOW_SIZE} seconds.")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 30)

def watch_log():
    """Simulates 'tail -f' behavior to read new log lines in real-time."""
    print(f"[*] Mini SIEM started. Monitoring {LOG_FILE_PATH}...")
    
    # Create a dummy log file if it doesn't exist
    if not os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, "w") as f:
            f.write("# Mini SIEM Log Started\n")

    with open(LOG_FILE_PATH, "r") as f:
        # Go to the end of the file
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)  # Sleep briefly to avoid maxing out CPU
                continue
                
            # Process the new line
            ip = parse_log_line(line)
            if ip:
                correlation_engine(ip)

if __name__ == "__main__":
    try:
        watch_log()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Mini SIEM. Stay safe!")
