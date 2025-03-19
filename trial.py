import time
import re
import os 
import subprocess
from datetime import datetime

# Tail the log file to check any update on incoming traffic
def tail_conpot(filename):
    with open(filename, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                continue
            yield line

def process_line(line):
    # For Modbus scan:
    port_on = re.search(r"\*? server started on:\s+\('([\d.]+)',\s*(\d+)\)", line)
    modbus_scan = re.search(r"New Modbus connection from\s+([\d.]+):(\d+)\.\s+\(([a-fA-F0-9\-]+)\)", line)
    if port_on:
        IP = port_on.group(1)
        port = port_on.group(2)
        if port == "502":
            print(f"Modbus on from {IP}:{port}")
        elif port == "102":
            print(f"S7comm on from {IP}:{port}")
        elif port == "44818":
            print(f"ENIP on from {IP}:{port}")
    elif modbus_scan:
        IP = modbus_scan.group(1)
        port = modbus_scan.group(2)
        session_id = modbus_scan.group(3)
        print(f"Modbus scan from {IP}:{port} with session ID {session_id}")

    # For S7Comm scan:
    s7_match = re.search(r"Modbus server started on:\s+\('([\d.]+)',\s*(\d+)\)", line)
    if s7_match:
        ip = s7_match.group(1)
        print(f"Detected S7Comm scan from IP {ip}")


    # For ENIP scan:
    enip_match = re.search(r"ENIP .*?on:\s+\(.*?,\s*(\d+)\)", line)
    if enip_match:
        port = enip_match.group(1)
        print(f"Detected ENIP scan on port {port}")

if __name__ == "__main__":
    try:
        dir_path = os.getcwd()
        log_file = dir_path + "/conpot.log"  # Update this with the actual path to your conpot.log file
        template = dir_path + "/conpot_profiles/Base_profiles/S7-1200"
        base_process = subprocess.Popen(["conpot", "-f", "--template", template], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Starting to tail log file for scanning activity...")
        print(log_file)
        for log_line in tail_conpot(log_file):
            process_line(log_line)     
    except (KeyboardInterrupt, Exception) as e:
        base_process.kill()
        print(f"Exiting Conpot due to: {e}")
        log_folder = dir_path + "/log"
        if not os.path.exists(log_folder):
            os.makedirs(log_folder)
        subprocess.run(["cp", log_file, log_folder + "/" + "log_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"])
        open('conpot.log', 'w').close()
        print("Log file moved to log folder")
