import os
import subprocess
import time
import socket
import ssl
import threading
import signal
import shutil

INTERFACE = "ens33"
REMOTE_IP = "192.168.220.128"
REMOTE_PORT = 8443
CERT_PATH = "/home/mw21030/cert.pem"  # adjust these paths
KEY_PATH = "/home/mw21030/key.pem"
LOG_DIR = "/tmp/snortlog"

snort_proc = None
sock_listener = None

def run(cmd):
    print(f"[CMD] {cmd}")
    subprocess.run(cmd, shell=True)

def setup_promiscuous_mode():
    print(f"[+] Enabling promiscuous mode on {INTERFACE}...")
    run(f"sudo ip link set {INTERFACE} promisc on")

def start_snort():
    global snort_proc
    print("[+] Preparing Snort log directory...")
    if not os.path.exists(LOG_DIR):
       os.makedirs(LOG_DIR, exist_ok=True)

    print("[+] Starting Snort on interface:", INTERFACE)
    snort_cmd = f"sudo snort -i {INTERFACE} -A fast -c /etc/snort/snort.conf -l {LOG_DIR}"
    snort_proc = subprocess.Popen(snort_cmd, shell=True)

def tail_alerts_and_forward():
    alert_path = f"{LOG_DIR}/alert"
    print("[+] Waiting for Snort alerts...")
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

def listen_for_shutdown_signal():
    global sock_listener
    print("[+] Listening for shutdown signal from remote...")
    sock_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_listener.bind(('', 9999))
    sock_listener.listen(1)
    conn, addr = sock_listener.accept()
    msg = conn.recv(1024).decode()
    if "shutdown" in msg.lower():
        print("[!] Shutdown signal received.")
        cleanup()

def cleanup():
    print("[*] Cleaning up...")
    try:
        if snort_proc: snort_proc.terminate()
        if sock_listener: sock_listener.close()
    except:
        pass
    run(f"sudo ip link set {INTERFACE} promisc off")
    if os.path.exists(LOG_DIR):
        shutil.rmtree(LOG_DIR)
    print("[✔] Cleanup complete.")
    exit(0)

def signal_handler(sig, frame):
    print("\n[!] Caught interrupt. Exiting...")
    cleanup()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

setup_promiscuous_mode()
start_snort()

# Threads for alert forwarding and shutdown listener
threading.Thread(target=tail_alerts_and_forward, daemon=True).start()
threading.Thread(target=listen_for_shutdown_signal, daemon=True).start()

# Block main thread
while True:
    time.sleep(1)
