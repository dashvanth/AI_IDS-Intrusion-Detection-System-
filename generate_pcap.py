from scapy.all import wrpcap, Ether, IP, TCP, UDP
import random

def generate_sample_pcap(filename="data/test_attack.pcap", count=100):
    print(f"[*] Generating {count} packets to {filename}...")
    packets = []
    
    for _ in range(count):
        # 1. Normal Traffic (HTTP)
        if random.random() < 0.7:
            p = Ether()/IP(dst="192.168.1.5")/TCP(dport=80, flags="PA")
        
        # 2. Attack Traffic (DoS pattern simulation)
        else:
            p = Ether()/IP(dst="192.168.1.5")/TCP(dport=80, flags="S") # SYN Flood like
            
        packets.append(p)
        
    wrpcap(filename, packets)
    print(f"[+] Successfully created {filename}")

if __name__ == "__main__":
    generate_sample_pcap()
