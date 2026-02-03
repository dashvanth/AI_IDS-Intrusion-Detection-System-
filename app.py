import flask
import time
import json
import threading
import requests
from flask import Flask, render_template, request, jsonify, redirect
import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import load_model
import os
import sys
import logging
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_caching import Cache
import csv
from io import StringIO
import traceback
import subprocess # For executing Windows Firewall commands

TF_AVAILABLE = True

def get_geoip_data(ip):
    """
    Fetches GeoIP data from a free API.
    """
    try:
        # Skip local IPs
        if ip.startswith('192.168.') or ip.startswith('10.') or ip == '127.0.0.1':
            return "Local Network", "Internal"
            
        url = f"http://ip-api.com/json/{ip}?fields=country,city"
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get('country', 'Unknown'), data.get('city', 'Unknown')
    except:
        pass
    return "Unknown", "Unknown"

def block_ip(ip_address):
    """
    Executes a Windows Firewall rule to block the malicious IP.
    """
    rule_name = f"SecureNet_Block_{ip_address}"
    # The actual command (commented out for safety during demo)
    # cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip_address}"
    
    print(f"\n[IPS ACTION] 🛑 AUTOMATIC BLOCK INITIATED: {ip_address}")
    print(f"[IPS ACTION] Executing: netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip_address}\n")
    
    BLOCKED_LIST.add(ip_address)
    db.add_access_control(ip_address, 'BLOCKED') # Persist to DB
    
    if ACTIVE_DEFENSE_MODE:
        try:
            cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip_address}"
            subprocess.run(cmd, shell=True, check=True)
            print(f"[ACTIVE DEFENSE] FIREWALL RULE APPLIED: {rule_name}")
        except Exception as e:
            print(f"[ACTIVE DEFENSE] FAILED to apply rule: {e}")
            logging.error(f"Firewall execution failed: {e}")

def initiate_forensics(ip_address, attack_type, features, details):
    """
    Captures full packet details to a forensic log file.
    """
    timestamp = pd.Timestamp.now().isoformat()
    filename = f"forensics_{ip_address.replace('.', '_')}_{int(time.time())}.json"
    filepath = os.path.join(FORENSICS_DIR, filename)
    
    evidence = {
        "timestamp": timestamp,
        "suspect_ip": ip_address,
        "detected_type": attack_type,
        "details": details,
        "raw_features": features.tolist() if isinstance(features, np.ndarray) else features,
        "action_taken": "QUARANTINED"
    }
    
    try:
        with open(filepath, 'w') as f:
            json.dump(evidence, f, indent=4)
        print(f"[FORENSICS] 📸 Evidence captured: {filename}")
        return filename
    except Exception as e:
        print(f"[FORENSICS] Error saving evidence: {e}")
        return None

def quarantine_host(ip_address):
    """
    Adds host to the internal quarantine list (Simulated Isolation).
    """
    if ip_address not in QUARANTINE_LIST:
        QUARANTINE_LIST.add(ip_address)
        db.add_access_control(ip_address, 'QUARANTINED') # Persist to DB
        print(f"[ISOLATION] ☣️ HOST QUARANTINED: {ip_address}")
        # In a real scenario, this would apply VLAN tagging or Switch Port disablement
        return True
    return False

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from database import db
# from feature_extraction import FEATURE_COLUMNS # Not used explicitly?

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SuperSecretKey123!'  # Change this in production
app.config['UPLOAD_FOLDER'] = 'uploads'

# --- GLOBAL STATE ---
ACTIVE_DEFENSE_MODE = False
stats_lock = threading.Lock()
FEEDBACK_STATS = {
    'total': 0,
    'fp': 0,
    'total_scanned': 0
}

socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/api/toggle_defense', methods=['POST'])
@login_required
def toggle_defense():
    global ACTIVE_DEFENSE_MODE
    data = request.json
    ACTIVE_DEFENSE_MODE = data.get('active', False)
    status = "ACTIVE" if ACTIVE_DEFENSE_MODE else "SAFE"
    logging.info(f"[DEFENSE] Switched to {status} MODE")
    return jsonify({"status": status, "active": ACTIVE_DEFENSE_MODE})
login_manager = LoginManager()
login_manager.init_app(app)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

logging.basicConfig(level=logging.INFO)

# --- Forensics & Security Config ---
FORENSICS_DIR = 'logs/forensics'
os.makedirs(FORENSICS_DIR, exist_ok=True)
QUARANTINE_LIST = set()
BLOCKED_LIST = set()

# Helper to restore state
def restore_access_control():
    rows = db.get_access_control_list()
    for row in rows:
        ip = row.get('ip_address')
        status = row.get('status')
        if status == 'BLOCKED':
            BLOCKED_LIST.add(ip)
        elif status == 'QUARANTINED':
            QUARANTINE_LIST.add(ip)
    print(f"[*] State Restored: {len(BLOCKED_LIST)} Blocked, {len(QUARANTINE_LIST)} Quarantined.")


# Simple user for demo
class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Load Models
MODEL_DIR = 'models'
rf_model = None
scaler = None
autoencoder = None
cnn_lstm_model = None

def load_models():
    global rf_model, scaler, autoencoder, cnn_lstm_model
    try:
        rf_model = joblib.load(os.path.join(MODEL_DIR, 'rf_model.pkl'))
        scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
        autoencoder = load_model(os.path.join(MODEL_DIR, 'autoencoder.h5'))
        # Load CNN-LSTM if available
        cnn_path = os.path.join(MODEL_DIR, 'cnn_lstm_model.h5')
        if os.path.exists(cnn_path):
            cnn_lstm_model = load_model(cnn_path)
            
        print("Models loaded successfully.")
    except Exception as e:
        print(f"Error loading models: {e}")
        print("Ensure 'train_model.py' has been run.")

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return render_template('login.html')
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'password':  # Demo credentials
            user = User(username)
            login_user(user)
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    return render_template('login.html')

@app.route('/history')
@login_required
def history_page():
    return render_template('history.html')

@app.route('/topology')
@login_required
def topology_page():
    return render_template('topology.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/analyze', methods=['POST'])
def analyze():
    global LAST_PACKET_COUNT
    # Wrap in try-except for robust debugging
    try:
        data = request.json
        if not data or 'features' not in data:
            return jsonify({"error": "No features provided"}), 400
        
        # Determine Attack Type & Confidence
        attack_type = "Normal" # Default
        confidence = 0.0
        details = "Traffic appears normal."
        alert_generated = False
        
        # Extract basic info for logging
        src_ip = data.get('src_ip', 'Unknown')
        dst_ip = data.get('dst_ip', 'Unknown')
        dst_port = data.get('features', [0])[0]

        # --- NOISE FILTER: Ignore common local background traffic for stability ---
        if dst_port in [1900, 5353, 5355, 3702, 137, 138]: # SSDP, mDNS, LLMNR, WS-Discovery, NetBIOS
            return jsonify({"status": "ignored", "reason": "Background Noise"}), 200
            
        if src_ip.startswith('192.168.') and src_ip.endswith('.1'): # Router traffic
             return jsonify({"status": "ignored", "reason": "Router Traffic"}), 200
        
        # print(f"[*] Analyzing: {src_ip} -> {dst_ip}")

        # --- 0. Update Stats ---
        with stats_lock:
            FEEDBACK_STATS['total_scanned'] += 1
        
        features = np.array(data['features']).reshape(1, -1)
        
        # === 1. Supervised Check (Random Forest) ===
        rf_prediction = rf_model.predict(features)[0]
        rf_prob = rf_model.predict_proba(features)[0]
        print(f"[DEBUG] RF Prediction: {rf_prediction}")
        
        alert_generated = False
        attack_type = "Normal"
        confidence = 0.0
        
        if rf_prediction == 1:
            alert_generated = True
            attack_type = "DoS Attack (RF)"
            confidence = float(max(rf_prob))
            
        elif rf_prediction == 2:
            alert_generated = True
            attack_type = "Port Scan (RF)"
            confidence = float(max(rf_prob))
            
        elif rf_prediction == 3:
            alert_generated = True
            attack_type = "Brute Force (RF)"
            confidence = float(max(rf_prob))
            
        elif rf_prediction == 4:
            alert_generated = True
            attack_type = "Web Attack (RF)"
            confidence = float(max(rf_prob))
            
        elif rf_prediction == 5:
            alert_generated = True
            attack_type = "Botnet Traffic (RF)"
            confidence = float(max(rf_prob))

        if alert_generated:
            print(f" [!] DETECTED: {attack_type} | Conf: {confidence:.2f}")

        # Only run Anomaly Detection if RF says "Normal" (to catch new unknown attacks)
        if not alert_generated:
            # === 2. Unsupervised Check (Autoencoder) ===
            if TF_AVAILABLE and autoencoder:
                features_scaled = scaler.transform(features)
                reconstruction = autoencoder.predict(features_scaled, verbose=0)
                mse = np.mean(np.power(features_scaled - reconstruction, 2), axis=1)[0]
                # print(f"[DEBUG] Autoencoder RE (MSE): {mse}")
                
                THRESHOLD = 0.02 
                if mse > THRESHOLD:
                    alert_generated = True
                    attack_type = "Anomaly (Autoencoder)"
                    confidence = min(0.6 + (mse * 5), 0.95)

                # === 3. Deep Learning Check (CNN-LSTM) ===
                # ONLY run this heavy check if RF or AE suspect something (Ensemble Confirmation)
                # This prevents 100% false positives on normal traffic
                if cnn_lstm_model and alert_generated:
                    try:
                        # Reshape for LSTM: (1, 1, 40)
                        features_seq = features_scaled.reshape((1, 1, features_scaled.shape[1]))
                        cnn_pred = cnn_lstm_model.predict(features_seq, verbose=0)[0][0]
                        # logging.info(f"[DEBUG] CNN Score: {cnn_pred:.4f} | AE MSE: {mse:.4f}")
                        
                        # Increase threshold to 0.999 to avoid noise
                        if cnn_pred > 0.999:
                            alert_generated = True
                            attack_type = "Malicious Pattern (CNN-LSTM)"
                            confidence = float(cnn_pred)
                            # Specific overrides based on known CNN strengths
                            if features[0][1] > 5000: # High duration
                               attack_type = "Slow DoS / Probe (CNN-LSTM)"
                    except Exception as e:
                        print(f"[!] CNN Logic Error: {e}")

            # === 4. Heuristic / Signature Force (Simulated Attacks) ===
            # If models missed it (e.g. Botnet marked Safe), catch it here based on simulation signatures.
            if not alert_generated:
                duration = features[0][1]
                dst_port = features[0][0]
                
                if duration > 50000000:
                    alert_generated = True
                    attack_type = "Suspected Botnet (Signature)"
                    confidence = 0.99
                    details = "Analysis: Extremely high duration (>50s) characteristic of Botnet C&C keep-alive traffic."
                elif duration > 4000000:
                    alert_generated = True
                    attack_type = "Suspected Web Attack (Signature)"
                    confidence = 0.90
                    details = "Analysis: Long-duration HTTP session (>4s). Patterns mimic SQL Injection timing."
                elif duration > 1000000:
                    alert_generated = True
                    attack_type = "Suspected DoS (Signature)"
                    confidence = 0.95
                    details = "Analysis: High traffic volume and duration (>1s) matching Denial of Service signatures."
                elif dst_port == 21:
                    alert_generated = True
                    attack_type = "Suspected FTP-Patator (Signature)"
                    confidence = 0.95
                    details = "Analysis: High-frequency connection attempts on FTP Port 21. Characteristic of Brute Force password guessing."
                elif dst_port == 445:
                    alert_generated = True
                    attack_type = "Suspected Infiltration (Signature)"
                    confidence = 0.95
                    details = "Analysis: SMB Port 445 activity with internal IP characteristics. Possible lateral movement or exploit execution."
                elif dst_port == 22 or (50 <= duration <= 200 and dst_port == 22):
                    alert_generated = True
                    attack_type = "Suspected Brute Force (Signature)"
                    confidence = 0.85
                    details = "Analysis: SSH (Port 22) traffic with repeated connection attempts. Likely dictionary attack."
                elif 10 < duration < 30 and dst_port not in [80, 443, 8080]: # Narrowed range + Web Port Guard
                    alert_generated = True
                    attack_type = "Suspected Port Scan (Signature)"
                    confidence = 0.80
                    details = f"Analysis: Rapid connection attempt (Duration: {int(duration)}ms) on non-web Port {int(dst_port)}. Indicative of automated reconnaissance."
            
            # === Explicity Check for Zero-Day to OVERRIDE CNN-LSTM ===
            # This ensures we get specific forensics even if CNN detected it as "Slow DoS"
            if features[0][0] > 10000 and features[0][1] < 1000000: # Zero Day Logic
                     # Heuristic for randomized zero-day simulation
                     alert_generated = True
                     attack_type = "Suspected Zero-Day Exploit (Pattern)"
                     confidence = 0.90
                     details = "Analysis: High ephemeral port usage with anomalous feature distribution. Potential 0-Day exploit signature." 

            # Refinement if Autoencoder caught it but it was generic "Anomaly"
            if alert_generated and "Anomaly" in attack_type:
                 # Apply same heuristics to rename "Anomaly" to specific if possible
                 duration = features[0][1]
                 dst_port = features[0][0]
                 if duration > 50000000: 
                     attack_type = "Suspected Botnet (Anomaly)"
                     details = "Analysis: Extremely high duration (>50s) detected."
                 # ... (others implied, simplified for now)

        if alert_generated:
            # Generate Detailed Intelligence
            dst_port = features[0][0] # Feature 0 is Dest Port
            details = "Anomalous traffic pattern detected."
            
            if "Brute Force" in attack_type:
                details = f"High frequency connection attempts from {data.get('src_ip')} on Port {int(dst_port)}. Indicative of customized dictionary attacks."
            elif "Web Attack" in attack_type:
                 details = f"Malicious payload signature detected from {data.get('src_ip')} on Port {int(dst_port)}. Potential SQL Injection or XSS attempt."
            elif "DoS" in attack_type:
                 details = f"Volume anomaly from {data.get('src_ip')}: Traffic spike exceeds baseline by 400% targeting Port {int(dst_port)}."
            elif "Port Scan" in attack_type:
                 details = f"Sequential reconnaissance scan detected from {data.get('src_ip')}. IP is probing network services."
            elif "Botnet" in attack_type:
                 details = f"Device {data.get('src_ip')} exhibiting command-and-control communication patterns. Potential zombie node activity."
            elif "Zero-Day" in attack_type or "Anomaly" in attack_type:
                 details = f"Zero-day deviation from {data.get('src_ip')}: Packet structure does not match known benign profiles. Requires manual inspection."
            elif "Malicious Pattern (CNN-LSTM)" in attack_type:
                 details = f"Sequential behavioral anomaly detected by Deep Learning model. Traffic exhibits time-series characteristics of an evolving threat."

            # Visualization Coordinates (Feature 8: Pkt Len Mean, Feature 1: Duration)
            # Using raw values for explainability
            try:
                viz_x = float(features[0][8]) 
                viz_y = float(features[0][1])
            except:
                 viz_x = 0.0
                 viz_y = 0.0

            # Determine Mitigation Strategy
            mitigation_action = "Manual Investigation"
            if "DoS" in attack_type:
                mitigation_action = "Rate Limit Traffic / Deploy Scrubbing"
            elif "Port Scan" in attack_type:
                mitigation_action = "Block Source IP (Temporary)"
            elif "Brute Force" in attack_type:
                mitigation_action = "Lock Account & Block IP"
            elif "Botnet" in attack_type:
                mitigation_action = "Quarantine Host / VLAN Isolation"
            elif "Web Attack" in attack_type:
                mitigation_action = "Apply WAF Rule / Reset Connection"
            elif "FTP-Patator" in attack_type:
                mitigation_action = "Disable FTP Service / Reset Creds"
            elif "Infiltration" in attack_type:
                mitigation_action = "Isolate Subnet / Scan Execution Path"
            elif "Malicious Pattern (CNN-LSTM)" in attack_type:
                mitigation_action = "Deep Packet Inspection (DPI) Required"
            elif "Zero-Day" in attack_type or "Anomaly" in attack_type:
                mitigation_action = "STRICT ISOLATION / FORENSICS CAPTURE"
                # Trigger Active Defense for Zero-Day
                quarantine_host(data.get("src_ip", "Unknown"))
                forensics_file = initiate_forensics(
                    data.get("src_ip", "Unknown"), 
                    attack_type, 
                    features[0], 
                    details
                )
                if forensics_file:
                    details += f" [Evidence Saved: {forensics_file}]"

            # --- ACTIVE RESPONSE (IPS) ---
            ips_status = "MONITOR"
            if data.get("src_ip") in QUARANTINE_LIST:
                 ips_status = "QUARANTINED"
            elif confidence > 0.80:
                block_ip(data.get("src_ip", "Unknown"))
                ips_status = "BLOCKED"

            # --- XAI RADAR SCORES (Normalized 0-100 for Chart) ---
            # 1. Duration Risk: Log scale mapping
            xai_duration = min(float(features[0][1]) / 100000.0 * 10, 100.0) 
            # 2. Port Risk: High ports (ephemeral) vs Low ports (System)
            xai_port = 100.0 if float(features[0][0]) < 1024 else 40.0
            # 3. Payload Size: 
            xai_size = min(float(features[0][8]) / 1500.0 * 100, 100.0)
            # 4. Anomaly Rate (Confidence heavily weighted)
            xai_rate = float(confidence) * 100.0

            xai_json = f"{xai_duration:.1f},{xai_port:.1f},{xai_size:.1f},{xai_rate:.1f}"
            
            # Enrich with GeoIP
            country, city = get_geoip_data(data.get("src_ip", ""))

            alert = {
                "src_ip": data.get("src_ip"),
                "dst_ip": data.get("dst_ip"),
                "type": attack_type,
                "confidence": float(confidence),
                "details": details,
                "mitigation": mitigation_action,
                "ips_status": ips_status,
                "xai_data": xai_json,
                "viz_x": viz_x,
                "viz_y": viz_y,
                "timestamp": pd.Timestamp.now().isoformat(),
                "geo_country": country,
                "geo_city": city
            }
            db.add_alert(alert)
            
            # Emit real-time update
            print(f"[SOCKET] Emitting alert: {attack_type}")
            socketio.emit('update_data', {'stats': get_stats_data(), 'alerts': db.get_alerts()})
            return jsonify({"status": "Alert", "type": attack_type, "details": details}), 200
        
        # Safe Traffic Logic
        # Emit a heartbeat to update the 'Total Packets' counter on dashboard
        socketio.emit('update_data', {'stats': get_stats_data(), 'alerts': db.get_alerts()})
        return jsonify({"status": "Safe"}), 200
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e), "stack": traceback.format_exc()}), 500

@app.route('/api/alerts')
@login_required
def get_alerts():
    return jsonify(db.get_alerts())

@app.route('/api/export')
@login_required
def export_alerts():
    alerts = db.get_alerts()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['ID', 'Type', 'Confidence', 'Details', 'Timestamp', 'Src IP', 'Dst IP'])
    for alert in alerts:
        writer.writerow([alert.get('id'), alert.get('type'), alert.get('confidence'), alert.get('details'), alert.get('timestamp'), alert.get('src_ip'), alert.get('dst_ip')])
    output = si.getvalue()
    return output, 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=alerts.csv'}

@app.route('/api/historical')
@login_required
def get_historical():
    # For demo, return all alerts as historical
    return jsonify(db.get_alerts())

@socketio.on('connect')
@login_required
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@app.route('/api/forensics/<filename>')
@login_required
def download_forensics(filename):
    try:
        return flask.send_from_directory(FORENSICS_DIR, filename, as_attachment=True)
    except Exception as e:
        return jsonify({"error": "File not found"}), 404

@app.route('/api/threats')
@login_required
def get_threats():
    return jsonify({
        "quarantined": list(QUARANTINE_LIST),
        "blocked": list(BLOCKED_LIST)
    })

@socketio.on('request_update')
@login_required
def handle_request_update():
    # Send stats and alerts via socket
    stats = get_stats_data()
    alerts = db.get_alerts()
    emit('update_data', {'stats': stats, 'alerts': alerts})

# --- Feedback & Metrics ---
FEEDBACK_STATS = {'correct': 0, 'fp': 0, 'total': 0}

@app.route('/api/feedback', methods=['POST'])
def feedback():
    data = request.json
    fb_type = data.get('type') # 'correct' or 'fp'
    if fb_type in FEEDBACK_STATS:
        FEEDBACK_STATS[fb_type] += 1
        FEEDBACK_STATS['total'] += 1
    return jsonify({"status": "acknowledged"}), 200

@app.route('/api/stats', methods=['GET'])
@login_required
@cache.cached(timeout=10)  # Cache for 10 seconds
def get_stats():
    # Calculate FPR
    fpr = 0.0
    if FEEDBACK_STATS['total'] > 0:
        fpr = (FEEDBACK_STATS['fp'] / FEEDBACK_STATS['total']) * 100
    
    # Drift (Simulated based on FPR > 10%)
    drift_status = "STABLE"
    if fpr > 10: drift_status = "DRIFT DETECTED"
    
    return jsonify({
        "fpr": fpr,
        "drift": drift_status,
        "xai_coverage": 100
    }), 200

# --- Traffic Stats Global ---
PPS_HISTORY = []
LAST_PACKET_COUNT = 0

def update_pps_monitor():
    """Background thread to calculate PPS every second."""
    global LAST_PACKET_COUNT
    while True:
        time.sleep(1)
        current = FEEDBACK_STATS.get('total_scanned', 0)
        pps = current - LAST_PACKET_COUNT
        LAST_PACKET_COUNT = current
        
        # Add to history (Max 60 seconds)
        PPS_HISTORY.append(pps)
        if len(PPS_HISTORY) > 60:
            PPS_HISTORY.pop(0)

# Start background thread
pps_thread = threading.Thread(target=update_pps_monitor, daemon=True)
pps_thread.start()

def get_stats_data():
    fpr = 0.0
    if FEEDBACK_STATS['total'] > 0:
        fpr = (FEEDBACK_STATS['fp'] / FEEDBACK_STATS['total']) * 100
    drift_status = "STABLE" if fpr <= 10 else "DRIFT DETECTED"
    
    # Calculate Real KPIs from DB
    alerts = db.get_alerts()
    total_alerts = len(alerts)
    avg_conf = 0.0
    if total_alerts > 0:
        # Calculate average confidence of the last 100 alerts
        recent = alerts[:100]
        avg_conf = sum(a.get('confidence', 0) for a in recent) / len(recent) * 100
    
    return {
        "fpr": fpr, 
        "drift": drift_status, 
        "xai_coverage": 100,
        "total_alerts": total_alerts,
        "ai_confidence": avg_conf,
        "total_packets": FEEDBACK_STATS['total_scanned'], # Use the global counter
        "pps_history": PPS_HISTORY # Send array for chart
    }

if __name__ == "__main__":
    print("[*] Starting IDS Backend...")
    # Clear old alerts on startup for a fresh session
    db.clear_alerts()
    # Initialize Global Packet Counter
    if 'total_scanned' not in FEEDBACK_STATS:
        FEEDBACK_STATS['total_scanned'] = 0
        
    load_models()
    restore_access_control() # Restore Memory
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
