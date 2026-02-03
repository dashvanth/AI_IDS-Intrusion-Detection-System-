import pandas as pd
import numpy as np
import os
import sys

# Add src to path to import feature columns
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from feature_extraction import FEATURE_COLUMNS

def generate_synthetic_data(num_samples=5000):
    """
    Generates synthetic traffic data for training.
    """
    print(f"Generating {num_samples} samples with {len(FEATURE_COLUMNS)} features...")
    
    # 0 = Normal, 1-5 = Attacks
    labels = np.random.choice([0, 1, 2, 3, 4, 5], size=num_samples, p=[0.5, 0.1, 0.1, 0.1, 0.1, 0.1])
    
    data = []
    
    for label in labels:
        row = {}
        if label == 0:
            # Generate "Normal" traffic patterns
            row['Destination Port'] = np.random.choice([80, 443, 53, 22])
            row['Flow Duration'] = np.random.normal(100, 20)
            row['Total Fwd Packets'] = np.random.randint(1, 20)
            row['Total Length of Fwd Packets'] = np.random.normal(500, 100)
            # ... randomize others slightly differently for normal
            for col in FEATURE_COLUMNS:
                if col not in row:
                    row[col] = abs(np.random.normal(10, 5))
        else:
            # Generate "Attack" traffic patterns based on label
            # 1: DoS, 2: PortScan, 3: BruteForce, 4: WebAttack, 5: Botnet
            row['Destination Port'] = np.random.choice([80, 8080, 21, 22]) 
            row['Flow Duration'] = np.random.normal(1000 + label*100, 50) 
            row['Total Fwd Packets'] = np.random.randint(100, 500)
            row['Total Length of Fwd Packets'] = np.random.normal(5000, 1000)
            
            for col in FEATURE_COLUMNS:
                if col not in row:
                    row[col] = abs(np.random.normal(100 + label*10, 50))
                    
        row['Label'] = label # Setup correctly for train_model.py (Title Case)
        data.append(row)
        
    df = pd.DataFrame(data)
    
    output_path = 'data/train_data.csv'
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Data saved to {output_path}")

if __name__ == "__main__":
    generate_synthetic_data()
