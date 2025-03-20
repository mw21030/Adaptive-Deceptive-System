import time
from scapy.all import sniff, IP, TCP, UDP

# Parameters: adjust these values based on your network and requirements
THRESHOLD_TARGETS = 5  # Number of distinct destination IPs that indicate a scan
TIME_WINDOW = 10       # Time window (in seconds) to count targets

# Dictionary to track scan attempts:
# Key: (protocol, source IP, destination port)
# Value: tuple (timestamp of first packet, set of destination IPs targeted)
scan_attempts = {}

def process_packet(packet):
    current_time = time.time()
    
    # Ensure the packet has an IP layer.
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    
    # Determine protocol and extract destination port
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        proto = "TCP"
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport
        proto = "UDP"
    else:
        return

    key = (proto, src_ip, dst_port)
    
    # Update tracking for this (protocol, source IP, destination port)
    if key not in scan_attempts:
        scan_attempts[key] = (current_time, {packet[IP].dst})
    else:
        start_time, target_ips = scan_attempts[key]
        # Reset tracking if time window has expired
        if current_time - start_time > TIME_WINDOW:
            scan_attempts[key] = (current_time, {packet[IP].dst})
        else:
            target_ips.add(packet[IP].dst)
            scan_attempts[key] = (start_time, target_ips)
            if len(target_ips) > THRESHOLD_TARGETS:
                print(f"Potential scan on {proto} port {dst_port} detected from {src_ip}.")
                print(f"Target IPs: {sorted(target_ips)}")

def detect_targeted_scanning():
    print("Starting to sniff for targeted scanning across IPs...")
    # Use a BPF filter to capture both TCP and UDP packets.
    sniff(filter="tcp or udp", prn=process_packet, store=0)

if __name__ == "__main__":
    detect_targeted_scanning()
