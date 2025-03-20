import time
import re
import os 
import subprocess
from datetime import datetime
import scapy 

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
    port_scan = re.search(r"New\s+(modbus|s7comm)\s+session\s+from\s+([\d.]+)\s+\(([a-fA-F0-9\-]+)\)", line)
    enip_on = re.search(r"handle server PID \[\s*(\d+)\s*\] starting on \('([\d.]+)',\s*(\d+)\)", line)
    enip_scan = re.search(r"EtherNet/IP CIP Request\s+\(Client\s+\('([\d.]+)',\s*(\d+)\)\):", line)
    if port_on:
        IP = port_on.group(1)
        port = port_on.group(2)
        if port == "502":
            print(f"Modbus on from {IP}:{port}")
        elif port == "102":
            print(f"S7comm on from {IP}:{port}")
    elif port_scan:
        Port = port_scan.group(1)
        IP = port_scan.group(2)
        session_id = port_scan.group(3)
        print(f"{Port} scan from {IP} with session ID {session_id}")
    elif enip_on:
        PID = enip_on.group(1)
        IP = enip_on.group(2)
        port = enip_on.group(3)
        print(f"ENIP on from {IP}:{port} with PID {PID}")
    elif enip_scan:
        IP = enip_scan.group(1)
        port = enip_scan.group(2)
        print(f"ENIP scan from {IP}:{port}")

def turn_on_conpot():
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


if __name__ == "__main__":
    try:
        dir_path = os.getcwd()
        log_file = dir_path + "/conpot.log"  # Update this with the actual path to your conpot.log file
        turn_on_conpot()
        print("Starting to tail log file for scanning activity...")
        print(log_file)
        for log_line in tail_conpot(log_file):
            process_line(log_line) 
    except (KeyboardInterrupt, Exception) as e:
        turn_off_conpot()
        print(f"Exiting Conpot due to: {e}")
        log_folder = dir_path + "/log"
        if not os.path.exists(log_folder):
            os.makedirs(log_folder)
        subprocess.run(["cp", log_file, log_folder + "/" + "log_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"])
        open('conpot.log', 'w').close()
        print("Log file moved to log folder")
