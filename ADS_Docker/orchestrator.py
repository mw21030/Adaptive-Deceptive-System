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

# Configure logging to include the timestamp, level, and message.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

# Configuration
HOST = '192.168.220.128'
in_useIP = [129, 1, 128, 35, 22, 7, 13]  # list of IP last octets already in use
PORT = 8443
SERVER_CERT = '/home/mw/server.pem'
SERVER_KEY = '/home/mw/server.key'
CA_CERT = '/home/mw/ca.pem'
deploy_conpot = {}  # Dictionary tracking deployed honeypot instances
stopDeploy = False  # Flag for graceful shutdown

# Locks to protect shared resources in a concurrent environment
ip_lock = threading.Lock()
deploy_lock = threading.Lock()

def start_base_conpot():
    subprocess.Popen("sudo docker-compose up -d", shell=True, start_new_session=True, stdin=subprocess.DEVNULL)
    logging.info("Base conpot instances started.")

def cleanup():
    subprocess.run("sudo docker-compose down", shell=True, stdin=subprocess.DEVNULL)
    with deploy_lock:
        for deploy in list(deploy_conpot.keys()):
            subprocess.run(f"docker rm -f {deploy}", shell=True, stdin=subprocess.DEVNULL)
            subprocess.run(f"rm -r ./Honeypot/Templates/{deploy}", shell=True, stdin=subprocess.DEVNULL)
            logging.info("Cleaned up conpot instance: %s", deploy)
    logging.info("Cleanup completed.")

def start_server():
    # Configure SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        sock.settimeout(60)  # Optional: timeout for idle socket operations
        logging.info(f"Server listening on {HOST}:{PORT}")

        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                try:
                    conn, addr = ssock.accept()
                    data = conn.recv(4096)
                    if data:
                        if stopDeploy:
                            conn.close()
                            logging.info("StopDeploy flag set. Shutting down server.")
                            break
                        else:
                            alert = data.decode()
                            logging.info("Received alert: %s", alert)
                            process_alert(alert)
                    conn.close()
                except ssl.SSLEOFError as e:
                    logging.warning("SSL connection closed unexpectedly: %s", e)
                    continue
                except Exception as e:
                    logging.error("Error: %s", e)

def removeconpot(template_name):
    with deploy_lock:
        if template_name in deploy_conpot:
            IP, port, vendor = deploy_conpot[template_name]
            subprocess.run(f"docker rm -f {template_name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ip_last_octet = int(IP.split('.')[-1])
            with ip_lock:
                if ip_last_octet in in_useIP:
                    in_useIP.remove(ip_last_octet)
            logging.info("Removed conpot instance with name: %s (IP: %s, port: %s)", template_name, IP, port)
            del deploy_conpot[template_name]
        else:
            logging.warning("No conpot instance found with name: %s", template_name)

def get_IP():
    with ip_lock:
        # Remove old deployments if too many IPs are in use
        if len(in_useIP) > 245:
            templates_to_remove = list(deploy_conpot.keys())[:10]
            for template_name in templates_to_remove:
                removeconpot(template_name)
        # Choose a random available IP (last octet from 1 to 255 not in use)
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
    # Build and deploy the honeypot instance using Docker commands.
    dir_path = os.getcwd()
    profiles_dir = os.path.join(dir_path, "Honeypot/Templates")
    template_path = os.path.join(profiles_dir, template_name)
    subprocess.run(f"docker build -t {template_name} {template_path}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(f"docker run -d --name {template_name} --net my_honeynet --ip {IP} {template_name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logging.info("Deployed conpot instance with name: %s (IP: %s, port: %s)", template_name, IP, port)
    with deploy_lock:
        deploy_conpot[template_name] = (IP, port, vendor)

def deploy_instance_for_alert(port, tcp=None):
    """ Helper function to get an IP, generate honeypot parameters,
        and deploy the instance. Optionally specify the tcp flag. """
    try:
        IP = get_IP()
        if tcp is None:
            template_name, vendor = cg.generate_conpot(port, IP)
        else:
            template_name, vendor = cg.generate_conpot(port, IP, tcp=tcp)
        honeypot_deploy(template_name, port, IP, vendor)
    except Exception as e:
        logging.error("Error deploying instance for port %s: %s", port, e)

def process_alert(alert):
    """ Process the incoming alert message and deploy honeypot instances in parallel
        using a thread pool executor. """
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = []
        if re.search(r"write operation attempt detected", alert, re.I):
            port_name = re.search(r"\[([a-zA-Z0-9]+)\]\s+write operation attempt detected", alert, re.I).group(1)
            port = port_number(port_name)
            futures = [executor.submit(deploy_instance_for_alert, port) for _ in range(3)]
        elif re.search(r"illegal control command detected", alert, re.I):
            port_name = re.search(r"\[([a-zA-Z0-9]+)\]\s+illegal control command detected", alert, re.I).group(1)
            port = port_number(port_name)
            futures = [executor.submit(deploy_instance_for_alert, port) for _ in range(3)]
        elif re.search(r"port scan attempt detected", alert, re.I) and not re.search(r"continuous", alert, re.I):
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                futures.append(executor.submit(deploy_instance_for_alert, port))
        elif re.search(r"continuous port scan detected", alert, re.I):
            port_name = re.search(r"\[([a-zA-Z0-9]+)\]\s+continuous port scan detected", alert, re.I).group(1)
            port = port_number(port_name)
            futures = [executor.submit(deploy_instance_for_alert, port) for _ in range(3)]
        elif re.search(r"generic UDP port scan detected", alert, re.I):
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                futures.append(executor.submit(deploy_instance_for_alert, port, tcp=False))
        elif re.search(r"generic TCP port scan detected", alert, re.I):
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                futures.append(executor.submit(deploy_instance_for_alert, port, tcp=True))
        elif re.search(r"potential volumetric attack detected", alert, re.I) or re.search(r"repeated connection attempts detected", alert, re.I):
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                futures.append(executor.submit(deploy_instance_for_alert, port))
        elif re.search(r"suspicious ENIP packet length detected", alert, re.I):
            port = 44818
            futures = [executor.submit(deploy_instance_for_alert, port) for _ in range(3)]
        elif re.search(r"minimal packet fingerprinting attempt detected", alert, re.I):
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                futures.append(executor.submit(deploy_instance_for_alert, port))
        # Wait for all parallel deployments to finish before exiting the function.
        concurrent.futures.wait(futures)

def main():
    logging.info("Starting conpot instances...")
    start_base_conpot()
    logging.info("Starting orchestrator...")
    start_server()

if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup()
