import pandas as pd
import numpy as np
import joblib
import os
import sys
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report
import tensorflow as tf
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import Dense, LSTM, Conv1D, MaxPooling1D, Flatten, Input, Dropout

# Add src to path to get feature list
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from feature_extraction import FEATURE_COLUMNS

# Configuration
DATA_FILES = [
    r"D:\capstone project\data\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    r"D:\capstone project\data\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    r"D:\capstone project\data\Friday-WorkingHours-Morning.pcap_ISCX.csv",
    r"D:\capstone project\data\Tuesday-WorkingHours.pcap_ISCX.csv",
    r"D:\capstone project\data\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
]
MODEL_DIR = 'models'
os.makedirs(MODEL_DIR, exist_ok=True)

def load_and_preprocess_data():
    print("Loading synthetic dataset...")
    file_path = 'data/train_data.csv'
    
    if not os.path.exists(file_path):
        raise ValueError(f"File {file_path} not found. Run 'generate_data.py' first.")
        
    df = pd.read_csv(file_path)
    
    # Ensure correct columns
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0
            
    # Keep only relevant columns + Label
    cols_to_keep = FEATURE_COLUMNS + ['Label']
    df = df[cols_to_keep]

    print(f"Class Distribution:\n{df['Label'].value_counts()}")
    return df

def train_models():
    df = load_and_preprocess_data()
    
    X = df[FEATURE_COLUMNS]
    y = df['Label']
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Scale
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save Scaler
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.pkl'))
    
    # === 1. Random Forest (Supervised) ===
    print("\nTraining Random Forest...")
    # Reduced Grid for speed
    param_grid = {
        'n_estimators': [50],
        'max_depth': [10, 20],
        'min_samples_split': [2, 5]
    }
    rf = RandomForestClassifier(random_state=42)
    grid_search = GridSearchCV(rf, param_grid, cv=3, n_jobs=-1, verbose=2)
    grid_search.fit(X_train, y_train)
    
    best_rf = grid_search.best_estimator_
    joblib.dump(best_rf, os.path.join(MODEL_DIR, 'rf_model.pkl'))
    print(f"Best RF Params: {grid_search.best_params_}")
    print("RF Report:\n", classification_report(y_test, best_rf.predict(X_test)))

    # === 2. Autoencoder (Unsupervised - Train on Normal Only) ===
    print("\nTraining Autoencoder...")
    # Get only normal training data
    X_train_normal = X_train_scaled[y_train == 0]
    
    input_dim = X_train.shape[1]
    encoding_dim = 14
    
    input_layer = Input(shape=(input_dim,))
    encoder = Dense(encoding_dim, activation="relu")(input_layer)
    decoder = Dense(input_dim, activation="sigmoid")(encoder) # Outputs 0-1 (scaled)
    
    autoencoder = Model(inputs=input_layer, outputs=decoder)
    autoencoder.compile(optimizer='adam', loss='mse')
    
    autoencoder.fit(
        X_train_normal, X_train_normal,
        epochs=10,
        batch_size=32,
        shuffle=True,
        validation_split=0.1,
        verbose=1
    )
    autoencoder.save(os.path.join(MODEL_DIR, 'autoencoder.h5'))

    # === 3. CNN-LSTM (Sequence - Reshaped) ===
    print("\nTraining CNN-LSTM...")
    # Reshape: (Samples, 1, 40)
    X_train_seq = X_train_scaled.reshape((X_train_scaled.shape[0], 1, X_train_scaled.shape[1]))
    X_test_seq = X_test_scaled.reshape((X_test_scaled.shape[0], 1, X_test_scaled.shape[1]))
    
    cnn_model = Sequential()
    cnn_model.add(Conv1D(filters=64, kernel_size=1, activation='relu', input_shape=(1, input_dim)))
    cnn_model.add(Dropout(0.5))
    cnn_model.add(LSTM(32, return_sequences=False))
    cnn_model.add(Dropout(0.5))
    cnn_model.add(Dense(1, activation='sigmoid'))
    
    cnn_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    
    cnn_model.fit(
        X_train_seq, y_train,
        epochs=5,
        batch_size=64,
        validation_data=(X_test_seq, y_test),
        verbose=1
    )
    cnn_model.save(os.path.join(MODEL_DIR, 'cnn_lstm_model.h5'))
    
    print("\nAll models trained and saved successfully.")

if __name__ == "__main__":
    try:
        train_models()
    except Exception as e:
        print(f"An error occurred: {e}")
