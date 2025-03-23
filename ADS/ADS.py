import time
import re
import os
import sqlite3
from datetime import datetime

# Database initialization function
def init_db(db_filename="attacker_events.db"):
    conn = sqlite3.connect(db_filename)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        attacker_ip TEXT,
                        port INTEGER,
                        event_type TEXT,
                        description TEXT
                      )''')
    conn.commit()
    return conn

# Function to record an event into the database
def record_event(conn, attacker_ip, port, event_type, description):
    cursor = conn.cursor()
    ts = datetime.now().isoformat()
    cursor.execute("INSERT INTO events (timestamp, attacker_ip, port, event_type, description) VALUES (?, ?, ?, ?, ?)",
                   (ts, attacker_ip, port, event_type, description))
    conn.commit()
    print(f"[{ts}] Recorded event: {attacker_ip} port {port} - {event_type} | {description}")

# In-memory counters (for simple frequency detection)
# You might want to reset these counters periodically (or use a time-window mechanism)
attack_counters = {
    "modbus": {},
    "s7comm": {},
    "enip": {}
}

# Thresholds (example values, adjust as needed)
THRESHOLDS = {
    "modbus": 5,   # e.g., more than 5 modbus events from an IP in a short period triggers extra action
    "s7comm": 3,
    "enip": 3
}

def tail_f(filename):
    """Generator that yields new lines as they are appended to the file."""
    with open(filename, 'r') as f:
        f.seek(0, 2)  # Move to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.01)  # slight sleep before retrying
                continue
            yield line

def update_counter(counter_dict, ip, protocol):
    count = counter_dict.get(ip, 0) + 1
    counter_dict[ip] = count
    return count

def process_line(line, db_conn):
    """
    Process a log line to check for scanning activity.
    Looks for patterns in log entries that indicate an attacker is scanning a port.
    """
    # Rule 1: Modbus scan detection
    # Look for a line indicating a new Modbus connection.
    modbus_match = re.search(r"New Modbus connection from\s+([\d.]+):(\d+)", line)
    if modbus_match:
        ip = modbus_match.group(1)
        port = int(modbus_match.group(2))
        description = "Modbus connection detected"
        count = update_counter(attack_counters["modbus"], ip, "modbus")
        print(f"Detected Modbus connection from {ip}:{port} (count={count})")
        record_event(db_conn, ip, port, "Modbus Scan", description)
        # Check if count exceeds threshold
        if count >= THRESHOLDS["modbus"]:
            print(f"High frequency Modbus scanning detected from {ip}. Consider deploying additional Modbus honeypots.")

    # Rule 2: S7Comm scan detection
    s7_match = re.search(r"New s7comm session from\s+([\d.]+)", line, re.IGNORECASE)
    if s7_match:
        ip = s7_match.group(1)
        port = 102  # Default S7Comm port
        description = "S7Comm session initiation detected"
        count = update_counter(attack_counters["s7comm"], ip, "s7comm")
        print(f"Detected S7Comm scan from {ip} (count={count})")
        record_event(db_conn, ip, port, "S7Comm Scan", description)
        if count >= THRESHOLDS["s7comm"]:
            print(f"High frequency S7Comm scanning detected from {ip}. Consider deploying additional S7 honeypots.")

    # Rule 3: ENIP scan detection
    enip_match = re.search(r"Found and enabled \('enip'.*?\)", line, re.IGNORECASE)
    # Alternatively, you might check for log messages that show ENIP server activity.
    if "Found and enabled ('enip'" in line:
        # For ENIP, we might not have the source IP in the log,
        # so you could assume a local test or extend the log format.
        ip = "unknown"  # or extract if available
        port = 44818  # Default ENIP port often used for EtherNet/IP
        description = "ENIP server activity detected"
        count = update_counter(attack_counters["enip"], ip, "enip")
        print(f"Detected ENIP activity (count={count})")
        record_event(db_conn, ip, port, "ENIP Scan", description)
        if count >= THRESHOLDS["enip"]:
            print("High frequency ENIP scanning detected. Consider deploying additional ENIP honeypots.")

    # Additional rule: Look for specific Modbus request patterns (example)
    modbus_req = re.search(r"Modbus traffic from\s+([\d.]+):.*'function_code':\s*(\d+)", line)
    if modbus_req:
        ip = modbus_req.group(1)
        func_code = int(modbus_req.group(2))
        description = f"Modbus request with function code {func_code}"
        # You might want to treat read (0x03) differently from write commands (0x06, 0x10)
        if func_code in [6, 16]:
            event_type = "Modbus Write Attempt"
        else:
            event_type = "Modbus Read/Probe"
        print(f"Detected {event_type} from {ip}, function code {func_code}")
        record_event(db_conn, ip, 502, event_type, description)

if __name__ == "__main__":
    # Set up DB connection
    db_conn = init_db()

    # Path to the conpot log file (update this path if needed)
    dir_path = os.getcwd()
    log_file = os.path.join(dir_path, "conpot.log")
    print("Starting to tail log file for scanning activity...")
    print(f"Log file: {log_file}")

    try:
        for log_line in tail_f(log_file):
            process_line(log_line, db_conn)
    except KeyboardInterrupt:
        print("Stopping log tailing...")
    finally:
        db_conn.close()
