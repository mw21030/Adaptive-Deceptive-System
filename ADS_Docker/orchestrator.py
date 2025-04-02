import docker
import time
import socket
import ssl
import re
import random
import conpot_generator as cg
import subprocess

HOST = '192.168.220.128'
in_useIP = [129,1,128,35,22,7,13]
PORT = 8443             # Must match REMOTE_PORT in your sender script
SERVER_CERT = '/home/mw/server.pem'
SERVER_KEY = '/home/mw/server.key'
CA_CERT = '/home/mw/ca.pem'

def start_base_conpot():
    try:
        subprocess.Popen(f"sudo docker-compose up -d", shell=True,start_new_session=True, stdin=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"Error starting base conpot: {e.stderr}")

def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"Server listening on {HOST}:{PORT}")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    data = conn.recv(4096)
                    if data:
                        process_alert(data.decode())
                        print(f"Received alert: {data.decode()}")
                        conn.close()
                except Exception as e:
                    print("Error:", e)

def get_IP():
    available_IP = [num for num in range(1, 256) if num not in in_useIP]
    IP = f"192.168.220.{random.choice(available_IP)}"
    in_useIP.append(int(IP.split('.')[-1]))
    return IP

def port_number(protocol):
    if protocol == "modbus":
        return 502
    elif protocol == "s7comm":
        return 102
    elif protocol == "enip":
        return 44818

def deploy_conpot(template_name):
    client = docker.from_env()
    try:
        container = client.containers.run(template_name, detach=True, auto_remove=True)
        print(f"Deployed conpot instance with ID: {container.id}")
        return container
    except docker.errors.APIError as e:
        print(f"Error deploying conpot instance: {e}")

def process_alert(alert):

    if re.search(r"write operation attempt detected", alert, re.I):
        port_name = re.search(r"\[([a-zA-Z0-9]+)\]\s+write operation attempt detected", alert, re.I).group(1)
        port = port_number(port_name)
        IP = get_IP()
        template_name = cg.generate_conpot(0,port,IP)



    elif re.search(r"illegal control command detected", alert, re.I):
        port = re.search(r"\[([a-zA-Z0-9]+)\]\s+illegal control command detected", alert, re.I)
        if m:
            protocol = m.group(1)
    elif re.search(r"port scan attempt detected", alert, re.I) and not re.search(r"continuous", alert, re.I):
        group = "Port Scan Attempts"
        m = re.search(r"\[([a-zA-Z0-9]+)\]\s+port scan attempt detected", alert, re.I)
        if m:
            protocol = m.group(1)
    elif re.search(r"continuous port scan detected", alert, re.I):
        group = "Continuous Scanning"
        m = re.search(r"\[([a-zA-Z0-9]+)\]\s+continuous port scan detected", alert, re.I)
        if m:
            protocol = m.group(1)
    elif ( re.search(r"potential volumetric attack detected", alert, re.I) or
           re.search(r"repeated connection attempts detected", alert, re.I) or
           re.search(r"generic TCP port scan detected", alert, re.I) or
           re.search(r"generic UDP port scan detected", alert, re.I) or
           re.search(r"minimal packet fingerprinting attempt detected", alert, re.I) or
           re.search(r"suspicious ENIP packet length detected", alert, re.I) ):
        group = "General Anomalous Behavior"
        # For general alerts, extract the first tag in square brackets (could be 'bruteforce', 'ddos', etc.)
        m = re.search(r"\[([a-zA-Z0-9]+)\]", alert)
        if m:
            protocol = m.group(1)
    else: group = "Unknown"

def main():
    start_server()
    print ("[+] Starting orchestrator...")
    start_base_conpot()
    print ("[+] Starting conpot instances...")
if __name__ == "__main__":
    main()
