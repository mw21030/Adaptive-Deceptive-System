import time
import re
import os 
import subprocess
import datetime

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
    modbus_on = re.search(r"Modbus server started on:\s+\(\'(\d+)\,\s*(\d+)\)", line)
    modbus_scan = re.search(r"New Modbus connection from\s+([\d.]+)\:（[\d.]+)\.\s+(([\d.]+)\)", line)
    if modbus_on:
        IP = modbus_on.group(1)
        port = modbus_on.group(2)
        print(f"Modpus on from {IP}:{port}")
    elif modbus_scan:
        IP = modbus_scan.group(1)
        port = modbus_scan.group(2)
        session_id = modbus_scan.group(3)
        print(f"Modbus scan from {IP}:{port} with session ID {session_id}")

    # For S7Comm scan:
    s7_match = re.search(r"new s7comm session from\s+([\d.]+)", line, re.IGNORECASE)
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
        base_process = subprocess.Popen(
        ["conpot -f --template ", template],
        stdout=subprocess.DEVNULL,  # Redirect stdout if you don't want terminal output
        stderr=subprocess.DEVNULL   # Redirect stderr as well
        )
        print("Starting to tail log file for scanning activity...")
        print(log_file)
        for log_line in tail_conpot(log_file):
            process_line(log_line)     
    except KeyboardInterrupt:
        base_process.terminate()
        print("Exiting Conpot...")
        log_folder = dir_path + "/log"
        if not os.path.exists(log_folder):
            os.makedirs(log_folder)
        subprocess.run(["mv", log_file, log_folder+ "/" +"log_"+ datetime.now().strftime("%Y%m%d_%H%M%S") + ".log"])        
