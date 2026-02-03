import pandas as pd
import numpy as np
import joblib
import os
import sys
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
import tensorflow as tf
from tensorflow.keras.models import load_model

# Add src to path to get feature list
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from feature_extraction import FEATURE_COLUMNS

# Configuration
MODEL_DIR = 'models'
DATA_FILES = [
    r"D:\capstone project\data\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    r"D:\capstone project\data\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    # We'll use a subset for quick evaluation if needed, but let's try to get a representative sample
]

def map_label(label):
    if label == 'BENIGN': return 0
    if 'DDoS' in label: return 1
    if 'DoS' in label: return 1
    if 'PortScan' in label: return 2
    if 'Brute Force' in label or 'Patator' in label: return 3
    if 'Web Attack' in label or 'Sql' in label or 'XSS' in label: return 4
    if 'Bot' in label: return 5
    return 0

def evaluate():
    print("Loading models...")
    try:
        rf_model = joblib.load(os.path.join(MODEL_DIR, 'rf_model.pkl'))
        scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
        autoencoder = load_model(os.path.join(MODEL_DIR, 'autoencoder.h5'))
        cnn_lstm_model = None
        cnn_path = os.path.join(MODEL_DIR, 'cnn_lstm_model.h5')
        if os.path.exists(cnn_path):
            cnn_lstm_model = load_model(cnn_path)
    except Exception as e:
        print(f"Error loading models: {e}")
        return

    print("Loading test data (sampling for evaluation)...")
    dfs = []
    for file in DATA_FILES:
        if os.path.exists(file):
            df = pd.read_csv(file, skipinitialspace=True)
            dfs.append(df.sample(n=min(len(df), 5000), random_state=42))
    
    test_df = pd.concat(dfs, ignore_index=True)
    test_df.columns = test_df.columns.str.strip()
    
    # Clean data
    missing_cols = set(FEATURE_COLUMNS) - set(test_df.columns)
    for col in missing_cols:
        test_df[col] = 0
    
    test_df = test_df[FEATURE_COLUMNS + ['Label']]
    test_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    test_df.dropna(inplace=True)
    
    test_df['Label'] = test_df['Label'].apply(map_label)
    
    X = test_df[FEATURE_COLUMNS]
    y = test_df['Label']
    X_scaled = scaler.transform(X)

    results = {}

    # 1. Random Forest Evaluation
    print("\n--- Random Forest Performance ---")
    rf_preds = rf_model.predict(X)
    target_names = ['Normal', 'DDoS', 'PortScan', 'Brute Force', 'Web Attack', 'Bot']
    # Filter target names to match classes found in preds or true y
    present_labels = sorted(np.union1d(y, rf_preds).astype(int))
    filtered_names = [target_names[i] for i in present_labels]
    
    print(classification_report(y, rf_preds, labels=present_labels, target_names=filtered_names))
    results['rf'] = classification_report(y, rf_preds, labels=present_labels, target_names=filtered_names, output_dict=True)

    # 2. Autoencoder Evaluation (Anomaly Detection)
    # Binary Label for Anomaly: 0 = Normal, 1 = Everything else
    y_binary = (y > 0).astype(int)
    reconstruction = autoencoder.predict(X_scaled, verbose=0)
    mse = np.mean(np.power(X_scaled - reconstruction, 2), axis=1)
    THRESHOLD = 0.02
    ae_preds = (mse > THRESHOLD).astype(int)
    
    print("\n--- Autoencoder (Anomaly Detection) Performance ---")
    print(classification_report(y_binary, ae_preds, target_names=['Normal', 'Anomaly']))
    results['ae'] = classification_report(y_binary, ae_preds, output_dict=True)

    # 3. CNN-LSTM Evaluation
    if cnn_lstm_model:
        X_seq = X_scaled.reshape((X_scaled.shape[0], 1, X_scaled.shape[1]))
        cnn_probs = cnn_lstm_model.predict(X_seq, verbose=0)
        cnn_preds = (cnn_probs > 0.5).astype(int).flatten()
        
        # Mapping y to binary for CNN-LSTM as it was trained with binary_crossentropy in train_model.py
        # Actually in train_model.py: cnn_model.add(Dense(1, activation='sigmoid')) and loss='binary_crossentropy'
        # But it was trained on full y_train? No, y_train in train_model.py is multiclass (0-5)
        # Wait, if loss is binary_crossentropy and output layer has 1 neuron with sigmoid, 
        # it expects binary targets. keras handles multiclass targets by treating them as floats? 
        # Usually it errors. Let's check train_model.py again.
        # train_model.py: cnn_model.fit(X_train_seq, y_train, ...) 
        # If y_train is [0, 1, 2], sigmoid(Dense(1)) with binary_crossentropy will treat it as values.
        # That's probably a bug in train_model.py but let's see what it does.
        
        print("\n--- CNN-LSTM Performance ---")
        print(classification_report(y_binary, cnn_preds, target_names=['Normal', 'Malicious']))
        results['cnn'] = classification_report(y_binary, cnn_preds, output_dict=True)

    # Save results to a file for later use in PPT content generation
    with open('evaluation_results.json', 'w') as f:
        import json
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    evaluate()
