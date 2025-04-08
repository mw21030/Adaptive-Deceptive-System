import docker
import time
import socket
import ssl
import re
import random
import conpot_generator as cg
import subprocess
import os
import logging
import threading
import concurrent.futures

HOST = '192.168.220.128'
in_useIP = [129, 1, 128, 35, 22, 7, 13]  
PORT = 8443
SERVER_CERT = '/home/mw/server.pem'
SERVER_KEY = '/home/mw/server.key'
CA_CERT = '/home/mw/ca.pem'
deploy_conpot = {} 

ip_lock = threading.Lock()
deploy_lock = threading.Lock()

def start_base_conpot():
    subprocess.Popen("sudo docker-compose up -d", shell=True, start_new_session=True, stdin=subprocess.DEVNULL)

def cleanup():
    subprocess.run("sudo docker-compose down", shell=True, stdin=subprocess.DEVNULL)
    with deploy_lock:
        for deploy in list(deploy_conpot.keys()):
            subprocess.run(f"docker rm -f {deploy}", shell=True, stdin=subprocess.DEVNULL)
            subprocess.run(f"rm -r ./Honeypot/Templates/{deploy}", shell=True, stdin=subprocess.DEVNULL)
    print("Cleanup completed.")

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
                        alert = data.decode()
                        print(f"Received alert: {alert}")
                        process_alert(alert)
                    conn.close()
                except Exception as e:
                    print("Error: %s", e)

def removeconpot(template_name):
    with deploy_lock:
        if template_name in deploy_conpot:
            IP, port, vendor = deploy_conpot[template_name]
            subprocess.run(f"docker rm -f {template_name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            IP_addr = int(IP.split('.')[-1])
            with ip_lock:
                if IP_addr in in_useIP:
                    in_useIP.remove(IP_addr)
            print(f"Removed conpot instance with name: {template_name} with IP: {IP} in port: {port}")
            del deploy_conpot[template_name]
        else:
            print(f"No conpot instance found with name: {template_name}")

def get_IP():
    with ip_lock:
        if len(in_useIP) > 245:
            templates_to_remove = list(deploy_conpot.keys())[:10]
            for template_name in templates_to_remove:
                removeconpot(template_name)
        available_IP = [num for num in range(1, 256) if num not in in_useIP]
        chosen = random.choice(available_IP)
        IP = f"192.168.220.{chosen}"
        in_useIP.append(chosen)
    return IP

def port_number(protocol):
    protocol = protocol.lower()
    if protocol == "modbus":
        return 502
    elif protocol == "s7comm":
        return 102
    elif protocol == "enip":
        return 44818

def honeypot_deploy(template_name, port, IP, vendor):
    dir_path = os.getcwd()
    profiles_dir = os.path.join(dir_path, "Honeypot/Templates")
    template_path = os.path.join(profiles_dir, template_name)
    subprocess.run(f"docker build -t {template_name} {template_path}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(f"docker run -d --name {template_name} --net my_honeynet --ip {IP} {template_name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Deployed conpot instance with name: {template_name} with IP: {IP} in port: {port}")
    with deploy_lock:
        deploy_conpot[template_name] = (IP, port, vendor)

def deploy_instance_for_alert(port, tcp=None):
    try:
        IP = get_IP()
        if tcp is None:
            template_name, vendor = cg.generate_conpot(port, IP)
        else:
            template_name, vendor = cg.generate_conpot(port, IP, tcp=tcp)
        honeypot_deploy(template_name, port, IP, vendor)
    except Exception as e:
        print(f"Error deploying instance for port {port}: {e}")

def process_alert(alert):
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        deploying = []
        if re.search(r"write operation attempt detected", alert, re.I):
            port_name = re.search(r"\[([a-zA-Z0-9]+)\]\s+write operation attempt detected", alert, re.I).group(1)
            port = port_number(port_name)
            deploying = [executor.submit(deploy_instance_for_alert, port) for _ in range(3)]
        elif re.search(r"illegal control command detected", alert, re.I):
            port_name = re.search(r"\[([a-zA-Z0-9]+)\]\s+illegal control command detected", alert, re.I).group(1)
            port = port_number(port_name)
            deploying = [executor.submit(deploy_instance_for_alert, port) for _ in range(3)]
        elif re.search(r"port scan attempt detected", alert, re.I) and not re.search(r"continuous", alert, re.I):
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                deploying.append(executor.submit(deploy_instance_for_alert, port))
        elif re.search(r"continuous port scan detected", alert, re.I):
            port_name = re.search(r"\[([a-zA-Z0-9]+)\]\s+continuous port scan detected", alert, re.I).group(1)
            port = port_number(port_name)
            deploying = [executor.submit(deploy_instance_for_alert, port) for _ in range(3)]
        elif re.search(r"generic UDP port scan detected", alert, re.I):
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                deploying.append(executor.submit(deploy_instance_for_alert, port, tcp=False))
        elif re.search(r"generic TCP port scan detected", alert, re.I):
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                deploying.append(executor.submit(deploy_instance_for_alert, port, tcp=True))
        elif re.search(r"potential volumetric attack detected", alert, re.I) or re.search(r"repeated connection attempts detected", alert, re.I):
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                deploying.append(executor.submit(deploy_instance_for_alert, port))
        elif re.search(r"suspicious ENIP packet length detected", alert, re.I):
            port = 44818
            deploying = [executor.submit(deploy_instance_for_alert, port) for _ in range(3)]
        elif re.search(r"minimal packet fingerprinting attempt detected", alert, re.I):
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                deploying.append(executor.submit(deploy_instance_for_alert, port))
        concurrent.futures.wait(deploying)

if __name__ == "__main__":
    try:
        print("Starting conpot instances...")
        start_base_conpot()
        print("Starting orchestrator...")
        start_server()
    except KeyboardInterrupt:
        print("Stopping orchestrator...")
    finally:
        cleanup()
