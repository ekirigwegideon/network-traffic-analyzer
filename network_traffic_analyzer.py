import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"
        print(f"[+] Packet: {ip_src} -> {ip_dst} | Protocol: {proto}")

print("Starting Network Traffic Analyzer...")
scapy.sniff(prn=packet_callback, store=False)
