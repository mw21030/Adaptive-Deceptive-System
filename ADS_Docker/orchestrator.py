import docker
import time
import socket
import ssl
import re
import random
import conpot_generator as cg
import subprocess
import os

HOST = '192.168.220.128'
in_useIP = [129,1,128,35,22,7,13]
PORT = 8443       
SERVER_CERT = '/home/mw/server.pem'
SERVER_KEY = '/home/mw/server.key'
CA_CERT = '/home/mw/ca.pem'
deploy_conpot = {}


def start_base_conpot():
    subprocess.Popen(f"sudo docker-compose up -d", shell=True,start_new_session=True, stdin=subprocess.DEVNULL)

def cleanup():
    subprocess.run(f"sudo docker-compose down ", shell=True, stdin=subprocess.DEVNULL)

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

def turn_on_base_conpot():
    dir_path = os.getcwd()
    profiles_dir = os.path.join(dir_path, "conpot_profiles/Base_profiles")
    folder_names = [name for name in os.listdir(profiles_dir)
                    if os.path.isdir(os.path.join(profiles_dir, name))]
    for folder in folder_names:
        template = dir_path + "/conpot_profiles/Base_profiles/" + folder
        subprocess.Popen(["conpot", "-f", "--template", template], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def honeypot_deploy(template_name, port, IP):
    dir_path = os.getcwd()
    profiles_dir = os.path.join("dir_path", "Honeypot/Templates")
    template_path = os.path.join(profiles_dir, template_name)
    result = subprocess.run(f"docker build -t {template_name} {template_path}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.wait() != 0:
        print(f"Error building Docker image for {template_name}")
    else:
        subprocess.Popen(f"docker run -d --name {template_name} --net my_honeynet --ip {IP} {template_name}", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Deployed conpot instance with name: {template_name} with IP: {IP} in port: {port}")
        deploy_conpot[template_name] += IP, port

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
    # print ("Starting conpot instances...")
    # start_base_conpot()
    # print ("Starting orchestrator...")
    # start_server()
    honeypot_deploy("s7-1200", 102, "192.168.220.35")
    

if __name__ == "__main__":
    try:
        main()
    finally:
        cleanup()
