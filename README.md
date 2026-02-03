# AI-Based Intrusion Detection System (IDS)
## Startup Guide

# List of all 40 Features used:
## the model takes exactly list of features for every input:

Destination Port
Flow Duration
Total Fwd Packets
Total Backward Packets
Total Length of Fwd Packets
Total Length of Bwd Packets
Fwd Packet Length Max
Fwd Packet Length Min
Fwd Packet Length Mean
Fwd Packet Length Std
Bwd Packet Length Max
Bwd Packet Length Min
Bwd Packet Length Mean
Bwd Packet Length Std
Flow Bytes/s
Flow Packets/s
Fwd PSH Flags
Bwd PSH Flags
Fwd URG Flags
Bwd URG Flags
Fwd Header Length
Bwd Header Length
Fwd Packets/s
Bwd Packets/s
Min Packet Length
Max Packet Length
### Prerequisites
*   Python 3.11+
*   MySQL Server (Running)
*   Administrator Privileges (for Sniffer)

### Step 1: Start the Backend (The Brain)
Open Terminal 1:
```bash
python app.py
```
*Wait until you see: `Running on http://127.0.0.1:5000`*

### Step 2: Open the Dashboard
Open your web browser and go to:
[http://localhost:5000](http://localhost:5000)

### Step 3: Start the Sniffer (The Eyes)
Open Terminal 2 (**Run as Administrator**):
```bash
cd "D:\capstone project"
python sniffer.py --iface "Wi-Fi"
```
*Replace "Wi-Fi" with your actual network interface name if different.*

### Technical Note: Real-Time Communication
**Does this project use Sockets?**
Yes, the project uses **Flask-SocketIO** (WebSockets).

**Why is it necessary?**
Standard websites require you to refresh the page to see new data ("Pull" model). For an Intrusion Detection System, seconds matter. WebSockets allow the backend to **"Push"** alerts to the dashboard instantly without you hitting refresh.

**Advantages:**
1.  **Zero Latency**: Alerts appear the millisecond they are detected.
2.  **Efficiency**: Reduces server load compared to constantly polling for updates.
3.  **Bi-directional**: Allows the server to send stats (like "Total Packets") continuously.

### Step 4: Run Attack Simulation (The Test)
Open Terminal 3:
```bash
python attack_simulation.py
```
*This will send fake attacks to test the dashboard.*

### Troubleshooting
*   **No Alerts?** Ensure `attack_simulation.py` is running.
*   **Database Error?** Ensure MySQL is running and credentials in `src/database.py` are correct.
*   **Sniffer Error?** Ensure you installed Npcap and are running as Admin.
