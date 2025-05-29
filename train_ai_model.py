import sqlite3
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import json
import os

DB_NAME = "process_logs.db"
MODEL_FILE = "ai_malware_detector.pkl"

# Consistent feature columns used for both training & prediction
FEATURE_COLUMNS = ["cpu_usage", "memory_usage", "thread_count", "open_files"]

def get_db_connection():
    """Connect to the local SQLite database."""
    return sqlite3.connect(DB_NAME)

def setup_malware_features_table():
    """
    Create the malware_features table if it doesn't exist.
    This table stores (sha256, feature_vector, label).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malware_features (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256 TEXT UNIQUE,
            feature_vector TEXT,
            label TEXT
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()

def insert_sample_data_if_empty():
    """
    If the table is empty, insert some sample rows
    so we can test the training pipeline.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM malware_features")
    (count,) = cursor.fetchone()
    
    if count == 0:
        print("🆕 No data found in 'malware_features'. Inserting sample rows for testing...")

        # Sample benign process
        sample_benign_features = {
            "cpu_usage": 10,
            "memory_usage": 50000,
            "thread_count": 5,
            "open_files": 3
        }
        cursor.execute("""
            INSERT INTO malware_features (sha256, feature_vector, label)
            VALUES (?, ?, ?)
        """, (
            "sample_sha_benign",
            json.dumps(sample_benign_features),
            "benign"
        ))

        # Sample malware process
        sample_malware_features = {
            "cpu_usage": 80,
            "memory_usage": 200000,
            "thread_count": 20,
            "open_files": 10
        }
        cursor.execute("""
            INSERT INTO malware_features (sha256, feature_vector, label)
            VALUES (?, ?, ?)
        """, (
            "sample_sha_malware",
            json.dumps(sample_malware_features),
            "malware"
        ))

        conn.commit()

    cursor.close()
    conn.close()

def load_data():
    """
    Load feature_vector and label from the malware_features table,
    then convert JSON feature vectors to a pandas DataFrame.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT feature_vector, label FROM malware_features")
    data = cursor.fetchall()
    cursor.close()
    conn.close()

    if not data:
        return pd.DataFrame(), np.array([])

    # Convert JSON feature vectors to DataFrame
    X_raw = pd.DataFrame([json.loads(row[0]) for row in data])
    y = np.array([1 if row[1] == "malware" else 0 for row in data])  # 1 = Malware, 0 = Benign

    # Ensure the columns are in the correct order
    for col in FEATURE_COLUMNS:
        if col not in X_raw.columns:
            X_raw[col] = 0  # If missing, add a default 0

    # Reindex the DataFrame to the correct column order
    X = X_raw[FEATURE_COLUMNS]

    return X, y

def train_model():
    """
    Train a RandomForestClassifier on the data in malware_features.
    Saves the model to 'ai_malware_detector.pkl'.
    """
    # Ensure table exists
    setup_malware_features_table()

    # Optional: Insert sample data if table is empty
    insert_sample_data_if_empty()

    # Load data
    X, y = load_data()

    if X.empty:
        print("❌ No data found in 'malware_features'. Please insert real or sample data.")
        return

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Save the model
    joblib.dump(model, MODEL_FILE)
    print(f"✅ AI Model Trained and Saved as '{MODEL_FILE}'!")

if __name__ == "__main__":
    train_model()
