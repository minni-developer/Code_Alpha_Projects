from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())  # Prints a summary of captured packets

# Capture network packets (requires sudo/admin privileges)
print("Starting network sniffer...")
sniff(prn=packet_callback, store=False)

#If you want to capture only specific protocols (e.g., TCP, UDP, ICMP)
#sniff(filter="tcp", prn=packet_callback, store=False)
