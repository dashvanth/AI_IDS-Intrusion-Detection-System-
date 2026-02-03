
# 🛡️ AI-IDS: AI-Driven Intrusion Detection System

<p align="center">
  <img src="assets/dashboard_overview.png" alt="Dashboard Overview" width="100%">
</p>

## 📖 Overview
**AI-IDS** is a next-generation security monitoring tool that combines **Deep Learning**, **Machine Learning**, and **Behavioral Analytics** to detect sophisticated cyber threats in real-time. Unlike traditional signature-based systems, AI-IDS can identify zero-day exploits and complex attack patterns using a multi-layered AI approach.

Key capabilities include:
- **XAI Radar**: Explainable AI visualization to understand *why* an alert was triggered.
- **Real-time Forensics**: Automated capture of suspicious packet payloads.
- **Active Defense**: Simulated firewall blocking and quarantine mechanisms.

---

## 📸 Screenshots

### 1. Active Threat Dashboard
Real-time monitoring of network traffic, threat classification, and AI confidence scores.
<p align="center">
  <img src="assets/dashboard_overview.png" alt="Dashboard" width="80%">
</p>

### 2. Threat Logs & Timeline
Detailed timeline of detected attacks with specific "Attack Type" (e.g., DoS, Port Scan) and "Mitigation" suggestions.
<p align="center">
  <img src="assets/dashboard_logs.png" alt="Threat Logs" width="80%">
</p>

### 3. Network Topology
Visual map of the network showing the relationship between potential attackers and targets.
<p align="center">
  <img src="assets/topology.png" alt="Topology" width="80%">
</p>

---

## 🚀 Features
- **Deep Learning Engine**:
    - **Autoencoder**: Unsupervised anomaly detection for zero-day threats.
    - **CNN-LSTM**: Spatial-temporal analysis for complex sequential attacks.
- **Signature Engine**: Random Forest Classifier for high-speed detection of known attacks (DoS, Brute Force).
- **Explainable AI (XAI)**: Visualizes risk factors (Duration, Port, Payload Size) to help analysts make fast decisions.
- **Safe Mode**: Automatically falls back to Random Forest if GPU/Deep Learning dependencies are missing.

---

## 🛠️ Tech Stack
- **Backend**: Python 3.13, Flask, Flask-SocketIO
- **AI/ML**: TensorFlow 2.16+, Scikit-learn, NumPy, Pandas
- **Frontend**: HTML5, CSS3, JavaScript (SocketIO Client)
- **Database**: MySQL (Alerts & Access Control)
- **Visualization**: Chart.js, Vis.js (Topology)

---

## 📥 Installation

### Prerequisites
- Python 3.10+ (Tested on 3.13)
- MySQL Server (Optional persistence, defaults to in-memory if not configured)

### Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/dashvanth/AI_IDS-Intrusion-Detection-System-.git
   cd AI_IDS-Intrusion-Detection-System-
   ```

2. **Set up Virtual Environment** (Recommended)
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/Mac:
   source .venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
   *Note: If you are on Python 3.13, ensure you install the compatible TensorFlow version or let `pip` handle the resolution.*

4. **Initialize Models**
   If this is your first run, generate the synthetic data and train the models:
   ```bash
   python generate_data.py
   python train_model.py
   ```

---

## 🚦 Usage

1. **Start the Backend**
   ```bash
   python app.py
   ```
   Access the dashboard at `http://localhost:5000`.

2. **Login**
   - **Username**: `admin`
   - **Password**: `password`

3. **Simulate Attacks**
   To see the system in action, run the attack simulation script in a separate terminal:
   ```bash
   python attack_simulation.py
   ```
   This will generate DoS, Port Scan, and other traffic patterns that the IDS will detect and display on the dashboard.

---

## 🤝 Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## 📄 License
This project is licensed under the MIT License.
