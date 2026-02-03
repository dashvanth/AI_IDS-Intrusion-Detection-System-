import mysql.connector
import threading
import os
from datetime import datetime
import time

# MySQL Configuration - CHANGE THESE IF NEEDED
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'NewPassword123!',
    'database': 'ids_db'
}

class AlertDatabase:
    def __init__(self):
        self.lock = threading.Lock()
        self._init_db()
        
    def _connect(self):
        """Helper to get a database connection."""
        try:
            return mysql.connector.connect(**DB_CONFIG)
        except mysql.connector.Error as err:
            # Check if database doesn't exist, try to create it
            if err.errno == 1049: # Unknown database
                self._create_database()
                return mysql.connector.connect(**DB_CONFIG)
            print(f"[!] MySQL Error: {err}")
            return None

    def _create_database(self):
        """Create the database if it doesn't exist."""
        try:
            # Connect without DB to create it
            temp_config = DB_CONFIG.copy()
            del temp_config['database']
            conn = mysql.connector.connect(**temp_config)
            cursor = conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
            conn.close()
            print(f"[*] Database '{DB_CONFIG['database']}' created.")
        except Exception as e:
            print(f"[!] Failed to create database: {e}")

    def _init_db(self):
        """Initialize the table."""
        with self.lock:
            conn = self._connect()
            if conn:
                try:
                    cursor = conn.cursor()
                    # Force recreation to ensure schema matches code (Added for Phase 4)
                    cursor.execute('DROP TABLE IF EXISTS alerts')
                    
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS alerts (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            src_ip VARCHAR(50),
                            dst_ip VARCHAR(50),
                            attack_type VARCHAR(100),
                            confidence FLOAT,
                            details TEXT,
                            viz_x FLOAT,
                            viz_y FLOAT,
                            timestamp VARCHAR(50),
                            mitigation VARCHAR(255),
                            ips_status VARCHAR(50),
                            xai_data VARCHAR(255),
                            geo_country VARCHAR(100),
                            geo_city VARCHAR(100)
                        )
                    ''')
                    # New Table for Persistence
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS access_control (
                            ip_address VARCHAR(50) PRIMARY KEY,
                            status VARCHAR(50), -- 'BLOCKED' or 'QUARANTINED'
                            timestamp VARCHAR(50)
                        )
                    ''')
                    conn.commit()
                    conn.close()
                    print("[*] MySQL Tables checked/created.")
                except Exception as e:
                    print(f"[!] Error initializing table: {e}")
            else:
                print("[!] Could not connect to MySQL. Ensure the server is running.")
            
    def add_alert(self, alert_data):
        """Adds a new alert to the database."""
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        with self.lock:
            conn = self._connect()
            if conn:
                try:
                    cursor = conn.cursor()
                    
                    sql = "INSERT INTO alerts (src_ip, dst_ip, attack_type, confidence, details, viz_x, viz_y, timestamp, mitigation, ips_status, xai_data, geo_country, geo_city) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    val = (
                        alert_data.get('src_ip', 'Unknown'),
                        alert_data.get('dst_ip', 'Unknown'),
                        alert_data.get('type', 'Unknown'),
                        alert_data.get('confidence', 0.0),
                        alert_data.get('details', 'No details available.'),
                        alert_data.get('viz_x', 0.0),
                        alert_data.get('viz_y', 0.0),
                        timestamp,
                        alert_data.get('mitigation', 'Investigate'),
                        alert_data.get('ips_status', 'MONITOR'),
                        alert_data.get('xai_data', '0,0,0,0'),
                        alert_data.get('geo_country', 'Unknown'),
                        alert_data.get('geo_city', 'Unknown')
                    )
                    cursor.execute(sql, val)
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print(f"[!] Error adding alert: {e}")
            
    def get_alerts(self, limit=50):
        """Retrieves the most recent alerts."""
        with self.lock:
            conn = self._connect()
            if conn:
                try:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute(f"SELECT * FROM alerts ORDER BY id DESC LIMIT {limit}")
                    rows = cursor.fetchall()
                    conn.close()
                    return rows
                except Exception as e:
                    print(f"[!] Error fetching alerts: {e}")
                    return []
            else:
                return []

    def clear_alerts(self):
        """Truncates the alerts table to start fresh."""
        with self.lock:
            conn = self._connect()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute("TRUNCATE TABLE alerts")
                    conn.commit()
                    conn.close()
                    print("[*] Database cleared (Session Reset).")
                except Exception as e:
                    print(f"[!] Error clearing database: {e}")

    # --- Access Control Persistence methods ---
    def add_access_control(self, ip, status):
        with self.lock:
            conn = self._connect()
            if conn:
                try:
                    cursor = conn.cursor()
                    sql = "INSERT IGNORE INTO access_control (ip_address, status, timestamp) VALUES (%s, %s, %s)"
                    val = (ip, status, datetime.now().isoformat())
                    cursor.execute(sql, val)
                    conn.commit()
                    conn.close()
                    print(f"[DB] Persisted {status} for {ip}")
                except Exception as e:
                    print(f"[!] Error updating access control: {e}")

    def get_access_control_list(self):
        with self.lock:
            conn = self._connect()
            if conn:
                try:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT * FROM access_control")
                    rows = cursor.fetchall()
                    conn.close()
                    return rows
                except Exception as e:
                    print(f"[!] Error fetching access control list: {e}")
                    return []
            return []

# Global instance
db = AlertDatabase()
