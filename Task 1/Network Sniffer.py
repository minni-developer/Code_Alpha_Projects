from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# Specify filters
TARGET_IP = None  # Set to an IP address (e.g., "192.168.1.1") to capture only that IP, or None for all
PROTOCOL_FILTER = ["TCP", "UDP"]  # Choose ["TCP"], ["UDP"], or both

def log_packet(packet):
    with open("packet_log.txt", "a", encoding="utf-8") as f:
        if IP in packet:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Capture timestamp
            packet_size = len(packet)  # Get packet size
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Apply filtering for target IP
            if TARGET_IP and (src_ip != TARGET_IP and dst_ip != TARGET_IP):
                return  # Skip packets that don't match

            log = f"[{timestamp}] Packet Size: {packet_size} bytes\n"
            log += f"Source: {src_ip} → Destination: {dst_ip}\n"

            # Protocol filtering
            if TCP in packet and "TCP" in PROTOCOL_FILTER:
                log += f"Protocol: TCP | Src Port: {packet[TCP].sport} → Dst Port: {packet[TCP].dport}\n"
            elif UDP in packet and "UDP" in PROTOCOL_FILTER:
                log += f"Protocol: UDP | Src Port: {packet[UDP].sport} → Dst Port: {packet[UDP].dport}\n"
            else:
                return  # Skip packet if it doesn't match the protocol filter

            log += "-" * 60 + "\n"
            f.write(log)
            print(log.strip())  # Print in real-time

# Start sniffing with filters applied
sniff(prn=log_packet, store=False)
