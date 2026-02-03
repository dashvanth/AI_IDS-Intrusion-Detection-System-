import mysql.connector
import os
import sys

# MySQL Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'NewPassword123!',
    'database': 'ids_db'
}

def clear_alerts():
    print("[*] Connecting to Database...")
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Truncate assumes the table exists
        print("[*] Clearing 'alerts' table...")
        cursor.execute("TRUNCATE TABLE alerts")
        
        conn.commit()
        conn.close()
        print("[+] Success! All old alerts have been successfully wiped.")
        print("[*] Your dashboard should now show 0 detections.")
        
    except mysql.connector.Error as err:
        print(f"[!] MySQL Error: {err}")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    clear_alerts()
