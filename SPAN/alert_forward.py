import sys
import os
import subprocess
import time
import socket
import ssl
from datetime import datetime
import shutil
import re


INTERFACE = "ens33"
REMOTE_IP = "192.168.220.128"
REMOTE_PORT = 8443
LOG_DIR = "/tmp/snortlog"

CLIENT_CERT = '/home/mw21030/client.pem'
CLIENT_KEY = '/home/mw21030/client.key'
CA_CERT = '/home/mw21030/ca.pem'

def setup():
    subprocess.run(f"sudo ip link set {INTERFACE} promisc on", shell=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    subprocess.Popen(f"sudo snort -i {INTERFACE} -A fast -c /etc/snort/snort.conf -l {LOG_DIR}", shell=True,start_new_session=True, stdin=subprocess.DEVNULL)

def tail_alerts():
    alert_path = os.path.join(LOG_DIR, "alert")
    while not os.path.exists(alert_path):
        time.sleep(1)

    last_sent = {}
    pattern = re.compile(
        r".*\[\*\*\]\s+\[1:[^\]]+\]\s+(.+?)\s+\[\*\*\].*\{(?:TCP|UDP)\}\s+"
        r"(\d{1,3}(?:\.\d{1,3}){3}):\d+\s+->\s+(\d{1,3}(?:\.\d{1,3}){3}):\d+"
    )
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = False

    with open(alert_path, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                alert_msg = line.strip()
                match = pattern.search(alert_msg)
                if match:
                    alert_text = match.group(1).strip()
                    source_ip = match.group(2)
                    dest_ip = match.group(3)

                    dedup_key = (alert_text, source_ip, dest_ip)
                    current_time = time.time()
                    last_time = last_sent.get(dedup_key, 0)
                    if current_time - last_time < 5:
                        last_sent[dedup_key] = current_time
                        continue
                    elif source_ip == REMOTE_IP:
                        continue
                    else:
                        last_sent[dedup_key] = current_time
                        try:
                            with socket.create_connection((REMOTE_IP, REMOTE_PORT), timeout=5) as raw_sock:
                                with context.wrap_socket(raw_sock, server_hostname=REMOTE_IP) as s:
                                    s.sendall(line.encode())
                        except Exception as e:
                            print(f"System is down")
                else :
                    try:
                        with socket.create_connection((REMOTE_IP, REMOTE_PORT), timeout=5) as raw_sock:
                            with context.wrap_socket(raw_sock, server_hostname=REMOTE_IP) as s:
                                s.sendall(line.encode())
                    except Exception as e:
                        print(f"System is down")
            else:
                time.sleep(0.5)

if __name__ == "__main__":
    setup()
    try:
        tail_alerts()
    finally:
        subprocess.run(f"sudo ip link set {INTERFACE} promisc off", shell=True)
        subprocess.run(f"sudo killall snort", shell=True)
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        alert_file = os.path.join(LOG_DIR, "alert")
        new_alert_file = os.path.join(LOG_DIR, f"alert_{now}")
        shutil.move(alert_file, new_alert_file)
        sys.exit(0)