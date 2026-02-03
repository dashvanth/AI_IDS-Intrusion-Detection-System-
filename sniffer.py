import sys
import os
import time
import requests
import logging
import argparse
from scapy.all import sniff, rdpcap, IP

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from feature_extraction import extract_features_from_packet

# Configuration
BACKEND_URL = "http://localhost:5000/analyze"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# State for sampling
packet_count = 0

def process_packet(packet):
    """
    Callback function for every captured packet with sampling to prevent lag.
    """
    global packet_count
    packet_count += 1
    
    # Only process 1 out of every 5 packets during live sniffing to prevent HTTP flooding
    if packet_count % 5 != 0:
        return

    try:
        # Only process IP traffic
        if not packet.haslayer(IP):
            return
            
        # Extract features
        features = extract_features_from_packet(packet)
        
        # Prepare payload
        payload = {
            "features": features,
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": int(packet[IP].proto),
            "len": int(packet[IP].len)
        }
        
        # Send to backend with generous timeout
        try:
            response = requests.post(BACKEND_URL, json=payload, timeout=3.0)
            if response.status_code == 200:
                logging.info(f"Analyzed: {packet[IP].src} -> {packet[IP].dst}")
            else:
                logging.warning(f"Backend Busy: {response.status_code}")
        except requests.exceptions.Timeout:
            logging.error("Backend Timeout: Inference engine is under heavy load.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error: {e}") 
            
    except Exception as e:
        logging.error(f"Processing Error: {e}")

def start_sniffer(interface=None, pcap_file=None):
    print(f"[*] Starting IDS Agent... Backend: {BACKEND_URL}")
    print("[*] Traffic Sampling: Active (Processing 20% of packets for stability)")
    
    if pcap_file:
        print(f"[*] Replaying PCAP file: {pcap_file}")
        try:
            packets = rdpcap(pcap_file)
            print(f"[*] Loaded {len(packets)} packets. Processing...")
            for pkt in packets:
                process_packet(pkt)
                # Sleep briefly to simulate real-time flow (optional)
                time.sleep(0.01) 
            print("[*] Replay finished.")
        except FileNotFoundError:
            print(f"[!] Error: File {pcap_file} not found.")
        except Exception as e:
            print(f"[!] Error reading PCAP: {e}")
            
    else:
        print("[*] Sniffing live traffic. Press Ctrl+C to stop.")
        # store=0 prevents memory leak
        sniff(filter="ip", prn=process_packet, store=0, iface=interface)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS Sniffer Agent")
    parser.add_argument("--pcap", type=str, help="Path to PCAP file to replay")
    parser.add_argument("--iface", type=str, help="Network interface to sniff on")
    
    args = parser.parse_args()
    
    start_sniffer(interface=args.iface, pcap_file=args.pcap)
