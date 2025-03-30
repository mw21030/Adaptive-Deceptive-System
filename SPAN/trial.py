import sys
import os
import subprocess
import time
import socket
import ssl
from datetime import datetime
import shutil


INTERFACE = "ens33"
REMOTE_IP = "192.168.220.128"
REMOTE_PORT = 8443
CERT_PATH = "/home/mw21030/cert.pem"  
KEY_PATH = "/home/mw21030/key.pem"
LOG_DIR = "/tmp/snortlog"

SHUTDOWN = False

def setup():
    subprocess.run(f"sudo ip link set {INTERFACE} promisc on", shell=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    subprocess.Popen(f"sudo snort -i {INTERFACE} -A fast -c /etc/snort/snort.conf -l {LOG_DIR}", shell=True)

def tail_alerts():
    alert_path = f"{LOG_DIR}/alert"
    while not os.path.exists(alert_path):
        time.sleep(1)

    with open(alert_path, 'r') as f:
        f.seek(0, os.SEEK_END)
        context = ssl.create_default_context()
        context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
        while True:
            line = f.readline()
            if line:
                print(f"[ALERT] {line.strip()}")
                try:
                    with socket.create_connection((REMOTE_IP, REMOTE_PORT), timeout=5) as raw_sock:
                        with context.wrap_socket(raw_sock, server_hostname=REMOTE_IP) as s:
                            s.sendall(line.encode())
                except Exception as e:
                    print(f"[-] Failed to send alert: {e}")
            else:
                time.sleep(0.5)

if __name__ == "__main__":
    setup()
    try:
        tail_alerts()
    except (KeyboardInterrupt, Exception) as e :
        subprocess.run(f"sudo ip link set {INTERFACE} promisc off", shell=True)
        subprocess.run(f"sudo killall snort", shell=True)
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        alert_file = f"{LOG_DIR}/alert"
        new_alert_file = f"{LOG_DIR}/alert_{now}"
        shutil.move(alert_file, new_alert_file)
        sys.exit(0)