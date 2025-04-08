#!/usr/bin/env python3
import time
from scapy.all import IP, TCP, UDP, Raw, send
import os
import datetime

# ---------- Modbus Attack Simulation ----------

def send_modbus_write(function_code):
    """
    Simulate a Modbus write command attempt.
    The payload includes a dummy header so that:
      - Bytes at offset 2-3: 0x00 0x00
      - Byte at offset 7: function code
    """
    # Construct a dummy payload that satisfies the rule criteria.
    # We add filler bytes ("AA") to ensure proper offsets.
    payload = b"\xAA\xAA" + b"\x00\x00" + b"\xAA\xAA" + bytes([function_code]) + b"\xAA"
    packet = IP(dst="192.168.220.7")/TCP(dport=502, flags="PA")/Raw(load=payload)
    send(packet)
    print(f"Modbus write command with function code {function_code:02X} sent.")

def send_modbus_illegal():
    # Use an illegal function code > 0x10 (e.g., 0x11)
    send_modbus_write(0x11)

def send_modbus_port_scan():
    """
    Simulate a port scan on Modbus by sending multiple SYN packets.
    """
    packet = IP(dst="192.168.220.7")/TCP(dport=502, flags="S")
    for i in range(5):
        send(packet, verbose=0)
        time.sleep(0.2)
    print("Modbus port scan simulation sent.")

# ---------- S7comm Attack Simulation ----------

def send_s7comm_write_variable():
    """
    Simulate a S7comm write variable request.
    Criteria:
      - At offset 7: b"32 01"
      - At offset 25: b"05"
    We construct a payload of at least 26 bytes.
    """
    payload = b"\xAA"*7 + b"\x32\x01" + b"\xAA"*(25-9) + b"\x05" + b"\xAA"
    packet = IP(dst="192.168.220.35")/TCP(dport=102, flags="PA")/Raw(load=payload)
    send(packet)
    print("S7comm write variable request sent.")

def send_s7comm_plc_command():
    """
    Simulate a S7comm PLC start/stop command by placing b"28 00" at offset 13.
    """
    payload = b"\xAA"*13 + b"\x28\x00" + b"\xAA"
    packet = IP(dst="192.168.220.35")/TCP(dport=102, flags="PA")/Raw(load=payload)
    send(packet)
    print("S7comm PLC start/stop command sent.")

def send_s7comm_port_scan():
    """
    Simulate a port scan on S7comm (TCP port 102) by sending multiple SYN packets.
    """
    packet = IP(dst="192.168.220.35")/TCP(dport=102, flags="S")
    for i in range(5):
        send(packet, verbose=0)
        time.sleep(0.2)
    print("S7comm port scan simulation sent.")

# ---------- ENIP Attack Simulation ----------

def send_enip_session_registration():
    """
    Simulate an ENIP session registration command by sending b"65 00" at the start.
    """
    payload = b"\x65\x00" + b"\xAA"
    packet = IP(dst="192.168.220.13")/TCP(dport=44818, flags="PA")/Raw(load=payload)
    send(packet)
    print("ENIP session registration command sent.")

def send_enip_unconnected_send():
    """
    Simulate an ENIP unconnected send command with b"52 00".
    """
    payload = b"\x52\x00" + b"\xAA"
    packet = IP(dst="192.168.220.13")/TCP(dport=44818, flags="PA")/Raw(load=payload)
    send(packet)
    print("ENIP unconnected send command sent.")

def send_enip_implicit_messaging():
    """
    Simulate an ENIP implicit messaging command by sending b"70 00" on UDP port 2222.
    """
    payload = b"\x70\x00" + b"\xAA"
    packet = IP(dst="192.168.220.13")/UDP(dport=2222)/Raw(load=payload)
    send(packet)
    print("ENIP implicit messaging command sent.")

def send_enip_write_tag_request():
    """
    Simulate an ENIP write tag request by sending b"4D 00".
    """
    payload = b"\x4D\x00" + b"\xAA"
    packet = IP(dst="192.168.220.13")/TCP(dport=44818, flags="PA")/Raw(load=payload)
    send(packet)
    print("ENIP write tag request sent.")

def send_enip_port_scan():
    """
    Simulate a port scan on ENIP by sending multiple SYN packets.
    """
    packet = IP(dst="192.168.220.13")/TCP(dport=44818, flags="S")
    for i in range(5):
        send(packet, verbose=0)
        time.sleep(0.2)
    print("ENIP port scan simulation sent.")

# ---------- High-Volume / Brute Force / DDoS Simulation ----------

def send_ddos():
    """
    Simulate a volumetric attack by sending 100 SYN packets within 1 second.
    """
    packet = IP(dst="192.168.220.7")/TCP(dport=502, flags="S")
    for i in range(100):
        send(packet, verbose=0)
    print("DDoS simulation complete.")

def send_bruteforce():
    """
    Simulate a brute force attack by sending 10 SYN packets (1 per second) to a target service.
    """
    packet = IP(dst="192.168.220.35")/TCP(dport=102, flags="S")
    for i in range(10):
        send(packet, verbose=0)
        time.sleep(1)
    print("Brute force simulation complete.")

# ---------- Main Execution: Attack Model Simulation ----------

if __name__ == "__main__":
    # Phase 1: Reconnaissance could be simulated with nmap or arp-scan externally.
    now = datetime.datetime.now()
    # Phase 2: Exploitation
    print("=== Phase 2: Exploitation ===")
    # send_modbus_write(0x05)
    # send_modbus_illegal()
    # time.sleep(1)
    
    # send_modbus_port_scan()
    # time.sleep(1)
    
    # send_s7comm_write_variable()
    # time.sleep(1)
    
    # send_s7comm_plc_command()
    # time.sleep(1)
    
    # send_s7comm_port_scan()
    # time.sleep(1)
    
    # send_enip_session_registration()
    # time.sleep(1)
    
    # send_enip_unconnected_send()
    # time.sleep(1)
    
    # send_enip_implicit_messaging()
    # time.sleep(1)
    
    # send_enip_write_tag_request()
    # time.sleep(1)
    
    send_enip_port_scan()
    # time.sleep(1)
    
    # # Phase 3: High-Volume / Brute Force / DDoS
    # print("=== Phase 3: High-Volume / Brute Force / DDoS ===")
    # send_ddos()
    # time.sleep(1)
    # send_bruteforce()

    finish = datetime.datetime.now() - now
    print(f"Time taken: {finish} seconds")
