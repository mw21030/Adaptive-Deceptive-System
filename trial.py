import time
import re
import os 
import subprocess
from datetime import datetime
import shutil

attack_counters = {
    "modbus": {},
    "s7comm": {},
    "enip": {}
}
TIME_WINDOW = 10
Trial_thresholds = 5
scan_attempts = {}

hosting_conpot = []


# Tail the log file to check any update on incoming traffic
def tail_conpot(filename):
    with open(filename, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def process_line(line):
    # For Modbus/S7comm scan:
    port_on = re.search(r"server started on:\s+\('([\d.]+)',\s*(\d+)\)", line)
    port_scan = re.search(r"New\s+(\w+)\s+connection\s+from\s+([\d\.]+):(\d+)\.\s+\(([a-fA-F0-9\-]+)\)", line)
    enip_on = re.search(r"handle server PID \[\s*(\d+)\s*\] starting on \('([\d.]+)',\s*(\d+)\)", line)
    enip_scan = re.search(r"EtherNet/IP CIP Request\s+\(Client\s+\('([\d.]+)',\s*(\d+)\)\):", line)
    key = ()
    if port_on:
        IP = port_on.group(1)
        port = port_on.group(2)
        if port == "502":
            print(f"Modbus on from {IP}:{port}")
        elif port == "102":
            print(f"S7comm on from {IP}:{port}")
    elif port_scan:
        print("in")
        port_name = port_scan.group(1)
        IP = port_scan.group(2)
        session_id = port_scan.group(4)
        if port_name == "Modbus":
            port = "502"
            key = (IP, port, time.time())
            print(f"Modbus scan from {IP}:{port} with session ID {session_id}")
        elif port_name == "S7":
            port = "102"
            key = (IP, port, time.time())
            print(f"S7comm scan from {IP}:{port} with session ID {session_id}")
    elif enip_on:
        PID = enip_on.group(1)
        IP = enip_on.group(2)
        port = enip_on.group(3)
        print(f"ENIP on from {IP}:{port} with PID {PID}")
    elif enip_scan:
        IP = enip_scan.group(1)
        port = 44818
        key = (IP, port, time.time())
        print(f"ENIP scan from {IP}:{port}")
    if key == ():
        return
    else:
        log_scan_activity(key[0], key[1], key[2])

def log_scan_activity(ip, port, timestamp):
    if port == "502":
        protocol = "Modbus"
    elif port == "102":
        protocol = "S7Comm"
    else:
        protocol = "ENIP"
    if ip not in scan_attempts:
        scan_attempts[ip] = {
            "first_seen": timestamp,
            "last_seen": timestamp,
            "scan_count": 1,
            "ports": {port},  # Store scanned ports as a set
            "protocols": {protocol},  # Store detected protocols as a set
            "attack_type": "Unknown"
        }
    else:
        if timestamp - scan_attempts[ip]["last_seen"] < 1 and protocol in scan_attempts[ip]["protocols"]:
            scan_attempts[ip]["last_seen"] = timestamp
        else:
            scan_attempts[ip]["last_seen"] = timestamp
            scan_attempts[ip]["scan_count"] += 1
            scan_attempts[ip]["ports"].add(port)
            scan_attempts[ip]["protocols"].add(protocol)

def detect_scan_activity():
    if not scan_attempts:
        time.sleep(0.1)
        return
    for key in list(scan_attempts.keys()):
        scan = scan_attempts[key]
        print (f"IP: {key}, Scan count: {scan['scan_count']}, Ports: {scan['ports']}, Protocols: {scan['protocols']}")
        if scan["scan_count"] >= Trial_thresholds:
            if len(scan["ports"]) == 1:
                print("Single Protocol detected")
                deploy_conpot(scan["ports"])
                scan["attack_type"] = "Targeted"
            else:
                print("Multiple Protocols detected")
                deploy_conpot(scan["ports"])
                scan["attack_type"] = "Multiple Protocols"


def turn_on_base_conpot():
    dir_path = os.getcwd()
    profiles_dir = os.path.join(dir_path, "conpot_profiles/Base_profiles")
    folder_names = [name for name in os.listdir(profiles_dir)
                    if os.path.isdir(os.path.join(profiles_dir, name))]
    for folder in folder_names:
        template = dir_path + "/conpot_profiles/Base_profiles/" + folder
        subprocess.Popen(["conpot", "-f", "--template", template], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # subprocess.Popen(["conpot", "-f", "--template", template1], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # template2 = dir_path + "/conpot_profiles/Base_profiles/modbus_trial"
    # subprocess.Popen(["conpot", "-f", "--template", template2], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # template3 = dir_path + "/conpot_profiles/Base_profiles/enip_trial"
    # subprocess.Popen(["conpot", "-f", "--template", template3], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def turn_off_conpot():
    subprocess.run(["pkill", "conpot"])

def deploy_conpot(port):
    print (port)
    dir_path = os.getcwd()
    no_to_deploy = int(3/len(port))
    for port in port:
        if port == "502":
            profiles_dir = dir_path + "/conpot_profiles/Deploy_profiles/modbus"
        elif port == "102":
            profiles_dir = dir_path + "/conpot_profiles/Deploy_profiles/s7comm"
        else:
            profiles_dir = dir_path + "/conpot_profiles/Deploy_profiles/enip"
        template_names = [name for name in os.listdir(profiles_dir)
                    if os.path.isdir(os.path.join(profiles_dir, name))]
        template_names = [name for name in template_names if name not in hosting_conpot]
        no_to_deploy = min(no_to_deploy, len(template_names))
        if no_to_deploy == 0:
            print ("No more templates to deploy")
            return
        else:
            print (f"Deploying {no_to_deploy} extra templates")
            for template in template_names[:no_to_deploy]:
                template_path = profiles_dir + template
                hosting_conpot.append(template)
                subprocess.Popen(["conpot", "-f", "--template", template_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("deployed extra conpot", template)
        
            



if __name__ == "__main__":
    try:
        dir_path = os.getcwd()
        log_file = dir_path + "/conpot.log"  # Update this with the actual path to your conpot.log file
        turn_on_base_conpot()
        print("Starting to tail log file for scanning activity...")
        print(log_file)
        for log_line in tail_conpot(log_file):
            process_line(log_line)
            detect_scan_activity()
    except (KeyboardInterrupt, Exception) as e:
        turn_off_conpot()
        print(f"Exiting Conpot due to: {e}")
        log_folder = dir_path + "/log"
        if not os.path.exists(log_folder):
            os.makedirs(log_folder)
        subprocess.run(["cp", log_file, log_folder + "/" + "log_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"])
        open('conpot.log', 'w').close()
        print("Log file moved to log folder")
