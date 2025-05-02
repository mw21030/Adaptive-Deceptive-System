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
import logging
from threading import Timer
from collections import defaultdict


ALERT_CACHE      = defaultdict(float)    
ALERT_CACHE_LOCK = threading.Lock()
DEDUP_WINDOW     = 5.0                  



TIMER_REGISTRY = []
stop_event     = threading.Event()


HOST = '192.168.220.128'
in_useIP = [129, 1, 128, 35, 22, 7, 13]  
PORT = 8443
SERVER_CERT = '/home/mw/server.pem'
SERVER_KEY = '/home/mw/server.key'
CA_CERT = '/home/mw/ca.pem'
deploy_conpot = {} 

ip_lock = threading.Lock()
deploy_lock = threading.Lock()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def start_base_conpot():
    subprocess.Popen("sudo docker-compose up -d", shell=True, start_new_session=True, stdin=subprocess.DEVNULL)

def cleanup():
    stop_event.set()
    logging.info("Shutting down orchestrator...")

    # Cancel timers
    for t in TIMER_REGISTRY:
        t.cancel()
    logging.info("All timers cancelled.")
    try:
        logging.info("Stopping docker-compose services...")
        result = subprocess.run("sudo docker-compose down", shell=True,stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        if result.returncode != 0:
            logging.warning("docker-compose down failed: %s", result.stderr.decode().strip())
        else:
            logging.info("docker-compose down completed successfully.")
    except subprocess.TimeoutExpired:
        logging.error("docker-compose down timed out. Forcing container shutdown...")
    with deploy_lock:
        for deploy in list(deploy_conpot.keys()):
            logging.info(f"Removing container: {deploy}")
            subprocess.run(f"docker rm -f {deploy}", shell=True, stdin=subprocess.DEVNULL)
            subprocess.run(f"rm -rf ./Honeypot/Templates/{deploy}", shell=True, stdin=subprocess.DEVNULL)
            subprocess.run(f"docker rmi -f {deploy}:latest", shell=True, stdin=subprocess.DEVNULL)
        deploy_conpot.clear()
    logging.info("Cleanup completed.")

def reconfigure_conpot(template_name, alter_IP=False):
    with deploy_lock:
        IP, port, vendor, profile = deploy_conpot[template_name]
    try:
        if alter_IP:
            IP = get_IP()
        new_name, new_vendor, new_profile = cg.reconfiguration(IP, port, profile)
        honeypot_deploy(new_name, port, IP, new_vendor, new_profile)
        removeconpot(template_name)           # only delete after success
    except Exception as e:
        logging.error("Reconfig failed: %s", e)

def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        logging.info(f"Server listening on {HOST}:{PORT}")

        while True:
            try:
                raw_conn, addr = sock.accept()
                with context.wrap_socket(raw_conn, server_side=True) as conn:
                    data = conn.recv(4096)
                    if data:
                        alert = data.decode()
                        logging.info(f"Received alert: {alert}")
                        process_alert(alert)
            except Exception as e:
                logging.error("Error: %s", e)


def rotate_conpot(template_name):
    with deploy_lock:
        IP, port, _, _ = deploy_conpot[template_name]
        removeconpot(template_name)
        IP = get_IP()
        new_name, new_vendor, new_profile = cg.generate_conpot(port, IP)
        honeypot_deploy(new_name, port, IP, new_vendor, new_profile)

def removeconpot(template_name):
    with deploy_lock:
        if template_name in deploy_conpot:
            IP, port, vendor, profile_info = deploy_conpot[template_name]
            subprocess.run(f"docker rm -f {template_name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(f"rm -r ./Honeypot/Templates/{template_name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(f"docker rmi -f {template_name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            IP_addr = int(IP.split('.')[-1])
            with ip_lock:
                if IP_addr in in_useIP:
                    in_useIP.remove(IP_addr)
            logging.info(f"Removed conpot instance with name: {template_name} with IP: {IP} in port: {port}")
            del deploy_conpot[template_name]
        else:
            logging.error(f"No conpot instance found with name: {template_name}")


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

def honeypot_deploy(template_name, port, IP, vendor, profile_info):
    dir_path = os.getcwd()
    profiles_dir = os.path.join(dir_path, "Honeypot/Templates")
    template_path = os.path.join(profiles_dir, template_name)
    subprocess.run(f"docker build -t {template_name} {template_path}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(f"docker run -d --name {template_name} --net my_honeynet --ip {IP} {template_name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logging.info(f"Deployed conpot instance with name: {template_name} with IP: {IP} in port: {port}")
    with deploy_lock:
        deploy_conpot[template_name] = (IP, port, vendor, profile_info)

def deploy_instance_for_alert(port, tcp=None, reconfigure = False, rotate=False, rotate_time =0):
    try:
        IP = get_IP()
        if tcp is None:
            template_name, vendor, profile_info = cg.generate_conpot(port, IP)
        else:
            template_name, vendor, profile_info = cg.generate_conpot(port, IP, tcp=tcp)
        honeypot_deploy(template_name, port, IP, vendor, profile_info)
        if rotate:
            rotate_sec = rotate_time * 60
            Timer(rotate_sec, rotate_conpot, args=(template_name,)).start()
    except Exception as e:
        logging.error(f"Error deploying instance for port {port}: {e}")



def process_alert(alert):
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        deploying = []
        alert_info = re.compile(
                    r"\[(\w+)\]\s"                       
                    r"([A-Za-z0-9 _/.\-:]+)\s"       
                    r"\[[^\]]+\].*"                      
                    r"\{.*?\}\s"                         
                    r"([\d.]+)(?:\:\d+)?\s->\s"          
                    r"([\d.]+)(?:\:\d+)?"                
                )
        alert_info = alert_info.search(alert)
        if not alert_info:
            return        
        tag, msg, src_ip, dst_ip = alert_info.groups()
        if not should_process(tag, msg, src_ip, dst_ip):
            logging.info("Dedup-drop <%s %s %s to %s>", tag, msg, src_ip, dst_ip)
            return
        if alert_info.group(1) == 'scan' or alert_info.group(1) == 'icmp':
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                deploying.append(executor.submit(deploy_instance_for_alert, port))
        # elif alert_info.group(2) == 'banner grabbing':
        #     for _ in range(3):
        #         port = random.choice([502, 102, 44818])
        #         deploying.append(executor.submit(deploy_instance_for_alert, port))
        # elif alert_info.group(2) == 'snmp enumeration detected':
        #     for _ in range(3):
        #         port = random.choice([502, 102, 44818])
        #         deploying.append(executor.submit(deploy_instance_for_alert, port))
        elif alert_info.group(2) == "fingerprinting detected":
            port = port_number(alert_info.group(1))
            for _ in range(3):
                rotate_time = random.randint(5, 10)
                deploying.append(executor.submit(deploy_instance_for_alert, port, rotate=True, rotate_time=rotate_time))
        elif alert_info.group(2) == "port scan detected":
            port = port_number(alert_info.group(1))
            for _ in range(3):
                deploying.append(executor.submit(deploy_instance_for_alert, port, rotate=True))
        elif alert_info.group(2) == "command spoofing detected":
            target = alert_info.group(4)
            matching_templates = [name for name, (ip, port, vendor, profile_info) in deploy_conpot.items() if ip == target]
            if matching_templates:
                template_name = matching_templates[0]
                reconfigure_conpot(template_name,reconfigure=True)
        elif alert_info.group(2) == "repeated connection attempts detected":
            target = alert_info.group(4)
            matching_templates = [name for name, (ip, port, vendor, profile_info) in deploy_conpot.items() if ip == target]
            if matching_templates: 
                template_name = matching_templates[0]
                with deploy_lock:
                    _, port, _, _ = deploy_conpot[template_name]
                for _ in range(3):
                    deploying.append(executor.submit(deploy_instance_for_alert, port, rotate=True))
                reconfigure_conpot(template_name, reconfigure=True)
        elif alert_info.group(2) == "flood detected":
            target = alert_info.group(4)
            matching_templates = [name for name, (ip, port, vendor, profile_info) in deploy_conpot.items() if ip == target]
            if matching_templates:
                template_name = matching_templates[0]
                reconfigure_conpot(template_name,alter_IP=True)
        elif alert_info.group(2) == "potential volumetric attack detected":
            for _ in range(3):
                port = random.choice([502, 102, 44818])
                deploying.append(executor.submit(deploy_instance_for_alert, port))
        concurrent.futures.wait(deploying)

def should_process(tag, msg, src, dst):
    key = (tag, msg, src, dst)
    now = time.time()
    with ALERT_CACHE_LOCK:
        last = ALERT_CACHE[key]
        if now - last < DEDUP_WINDOW:
            return False        
        ALERT_CACHE[key] = now    
    return True

def rotate_randam_conpot():
    number_rotate = random.randint(1,10)
    if number_rotate > len(deploy_conpot):
        number_rotate = len(deploy_conpot)
    for _ in range(number_rotate):
        with deploy_lock:
            if deploy_conpot:
                template_name = random.choice(list(deploy_conpot.keys()))
                IP, port, vendor, profile_info = deploy_conpot[template_name]
                removeconpot(template_name)
                IP = get_IP()
                template_name, vendor, profile_info = cg.generate_conpot(port, IP)
                honeypot_deploy(template_name, port, IP, vendor, profile_info)


def random_reconfigure():
    number_reconfigure = random.randint(5, 10)
    if number_reconfigure > len(deploy_conpot):
        number_reconfigure = len(deploy_conpot)
    for _ in range(number_reconfigure):
        with deploy_lock:
            if deploy_conpot:
                template_name = random.choice(list(deploy_conpot.keys()))
                reconfigure_conpot(template_name)


def _start_timer(seconds, func, *args):
    t = threading.Timer(seconds, func, args=args)
    t.daemon = True          # extra safety
    t.start()
    TIMER_REGISTRY.append(t)
    return t

def rotate():
    if stop_event.is_set():      # do not reschedule after Ctrl-C
        return
    mins = random.randint(45, 60)
    _start_timer(mins*60, rotate_randam_conpot)
    _start_timer(mins*60, rotate)

def random_reconfig():
    if stop_event.is_set():
        return
    mins = random.randint(5, 20)
    _start_timer(mins*60, random_reconfigure)
    _start_timer(mins*60, random_reconfig)

if __name__ == "__main__":
    try:
        logging.info("Starting conpot instances...")
        start_base_conpot()
        rotate()
        random_reconfig()
        logging.info("Starting orchestrator...")
        start_server()
    except KeyboardInterrupt:
        logging.info("Stopping orchestrator...")
    finally:
        cleanup()

