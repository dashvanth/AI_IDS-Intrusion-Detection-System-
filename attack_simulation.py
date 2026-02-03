import sys
import os
import time
import random
import requests
from scapy.all import IP, TCP, UDP, send

def simulate_attacks():
    """
    Simulates attacks by forcing packets onto the network interface.
    The sniffer should pick these up.
    """
    print("Starting Attack Simulation...")
    print("Press Ctrl+C to stop.")
    
    target_url = "http://localhost:5000/analyze"
    print(f"[*] Targeting Backend: {target_url}")
    
    # Pre-defined payloads mimicking real attack vectors
    
    try:
        while True:
            attack_type = random.choice(["DoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "FTP-Patator", "Infiltration", "Zero-Day", "Normal"])
            
            features = []
            payload = {}
            
            if attack_type == "DoS":
                print(f"[!] Simulating DoS/DDoS Attack...")
                features = [
                    80.0, 1293792.0, 3.0, 7.0, 26.0, 11607.0, 20.0, 0.0, 8.66, 10.26, 
                    5803.5, 0.0, 1658.14, 2190.0, 0.0, 7.72, 143754.6, 212571.6, 
                    643806.0, 3.0, 1293792.0, 646896.0, 4390.0, 649999.0, 643806.0, 
                    1290000.0, 215000.0, 368000.0, 1280000.0, 3.0, 0.0, 0.0, 
                    0.0, 0.0, 72.0, 232.0, 2.31, 5.41, 0.0, 5803.0
                ]
                payload = {
                    "features": features,
                    "src_ip": f"192.168.1.{random.randint(50, 200)}",
                    "dst_ip": "192.168.1.5",
                    "protocol": 6,
                    "len": 1500
                }
                    
            elif attack_type == "PortScan":
                print(f"[!] Simulating Port Scan...")
                features = [
                    float(random.choice([80, 443, 22, 21, 3389])), 49.0, 2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
                    0.0, 0.0, 0.0, 0.0, 0.0, 40816.32, 49.0, 0.0, 49.0, 49.0, 
                    49.0, 49.0, 0.0, 49.0, 49.0, 0.0, 0.0, 0.0, 0.0, 0.0, 
                    0.0, 0.0, 1.0, 0.0, 40.0, 0.0, 40816.32, 0.0, 0.0, 0.0
                ]
                
                payload = {
                    "features": features,
                    "src_ip": f"10.0.0.{random.randint(10, 99)}",
                    "dst_ip": "192.168.1.5",
                    "protocol": 6,
                    "len": 64
                }

            elif attack_type == "BruteForce":
                print(f"[!] Simulating Brute Force (SSH)...")
                features = [
                    22.0, 58.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 
                    0.0, 0.0, 0.0, 0.0, 34482.75, 34482.75, 58.0, 0.0, 
                    58.0, 58.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 
                    0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 32.0, 32.0, 17241.37, 
                    17241.37, 0.0, 0.0
                ]
                features[1] += random.uniform(0, 100) 
                payload = {
                    "features": features,
                    "src_ip": f"172.16.0.{random.randint(2, 20)}",
                    "dst_ip": "192.168.1.5",
                    "protocol": 6,
                    "len": 120
                }
                
            elif attack_type == "WebAttack":
                print(f"[!] Simulating Web Attack (SQL Injection)...")
                features = [
                    80.0, 5005378.0, 3.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 
                    0.0, 0.0, 0.0, 0.0, 0.0, 0.79914, 2502689.0, 2160000.0, 
                    4030000.0, 974000.0, 5000000.0, 2500000.0, 2160000.0, 
                    4030000.0, 974000.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 
                    0.0, 0.0, 0.0, 72.0, 32.0, 0.599, 0.199, 0.0, 0.0
                ]
                features[1] += random.uniform(0, 5000)
                payload = {
                    "features": features,
                    "src_ip": f"185.200.1.{random.randint(10, 50)}",
                    "dst_ip": "192.168.1.5",
                    "protocol": 6,
                    "len": 800
                }

            elif attack_type == "Botnet":
                print(f"[!] Simulating Botnet Traffic (Zombie Node)...")
                features = [8080.0, 60202640.0, 9.0, 9.0, 322.0, 256.0, 322.0, 0.0, 35.77777778, 107.3333333, 256.0, 0.0, 28.44444444, 85.33333333, 9.600907867, 0.29899021, 3541331.765, 4901981.331, 10200000.0, 47.0, 51200000.0, 6396441.875, 5268489.909, 10200000.0, 234.0, 60200000.0, 7518953.625, 4645137.318, 10300000.0, 637.0, 0.0, 0.0, 0.0, 0.0, 296.0, 296.0, 0.149495105, 0.149495105, 0.0, 322.0]
                payload = {
                    "features": features,
                    "src_ip": f"192.168.1.{random.randint(200, 250)}",
                    "dst_ip": "192.168.1.5",
                    "protocol": 6,
                    "len": 60
                }
                    

            
            elif attack_type == "FTP-Patator":
                print(f"[!] Simulating FTP-Patator (Brute Force Port 21)...")
                features = [0]*40
                features[0] = 21.0 # Port 21
                features[1] = random.uniform(500, 2000) # Medium duration
                features[3] = 10 # Flags
                payload = {
                     "features": features,
                     "src_ip": f"172.16.0.{random.randint(100, 200)}",
                     "dst_ip": "192.168.1.5",
                     "protocol": 6,
                     "len": 64
                }

            elif attack_type == "Infiltration":
                print(f"[!] Simulating Infiltration (Internal Scanning)...")
                features = [0]*40
                features[0] = 445.0 # SMB Port often used
                features[1] = random.uniform(100000, 500000) # Long duration file transfer?
                payload = {
                     "features": features,
                     "src_ip": "192.168.1.50", # Internal IP
                     "dst_ip": "192.168.1.5",
                     "protocol": 6,
                     "len": 1024
                }

            elif attack_type == "Zero-Day":
                print(f"[!] Simulating Zero-Day Exploit (Unknown Pattern)...")
                # Generate high-variance random noise to trigger Autoencoder
                features = [random.uniform(0, 100000) for _ in range(40)]
                features[0] = random.randint(10000, 65535) # High random port
                payload = {
                     "features": features,
                     "src_ip": f"203.0.113.{random.randint(1, 255)}",
                     "dst_ip": "192.168.1.5",
                     "protocol": 17, # UDP?
                     "len": random.randint(500, 1500)
                }

            else:
                print(f"[-] Simulating Normal Traffic...")
                features = [0]*40
                features[1] = random.uniform(10, 500) # Short duration
                payload = {
                    "features": features,
                    "src_ip": "192.168.1.5",
                    "dst_ip": "8.8.8.8",
                    "protocol": 6,
                    "len": 500
                }
                
            # SEND REQUEST
            try:
                response = requests.post(target_url, json=payload, timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "Alert":
                        print(f" >>> ALERT CONFIRMED: {data.get('type')}")
                    else:
                        print(f" >>> Safe: {data.get('status')}")
                else:
                    print(f" >>> ERROR {response.status_code}: {response.text}")
            except Exception as e:
                print(f" >>> REQUEST FAILED: {e}")
                
            time.sleep(1.0) # Slower to let us see output
            
    except KeyboardInterrupt:
        print("Simulation stopped.")
    except Exception as e:
        print(f"Fatal Error: {e}")

if __name__ == "__main__":
    simulate_attacks()
