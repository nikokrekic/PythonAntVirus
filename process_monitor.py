import psutil
import time
import sqlite3
import json
import os
import tkinter as tk
from tkinter import messagebox
import pefile
import win32api
import joblib
import pandas as pd
import requests
import sys  # <-- For command-line argument check

# ------------------------------------------------
# CONFIG: Discord Webhook URL
# ------------------------------------------------
DISCORD_WEBHOOK_URL = ""

DB_NAME = "process_logs.db"
WHITELIST_FILE = "whitelist.json"
TRUSTED_DEVELOPERS_FILE = "trusted_developers.json"
MODEL_FILE = "ai_malware_detector.pkl"

# ------------------------------------------------
# AI FEATURE COLUMNS
# ------------------------------------------------
FEATURE_COLUMNS = ["cpu_usage", "memory_usage", "thread_count", "open_files"]

# ------------------------------------------------
# DIRECTORIES & PROCESSES
# ------------------------------------------------
SUSPICIOUS_DIRS = [
    "C:\\Users\\", 
    "C:\\Temp\\", 
    "C:\\Windows\\Temp\\", 
    "C:\\AppData\\Local\\Temp\\",
]
SAFE_DIRS = [
    "C:\\Program Files", 
    "C:\\Program Files (x86)", 
    "C:\\Windows\\System32",
    os.path.expandvars("%LOCALAPPDATA%")
]
SYSTEM_PROTECTED_FILES = ["lsass.exe", "winlogon.exe", "svchost.exe"]
SYSTEM_IGNORE_PROCESSES = ["System Idle Process", "System", "Registry"]

# ------------------------------------------------
# DEFAULT TRUSTED DEVELOPERS
# ------------------------------------------------
DEFAULT_TRUSTED_DEVELOPERS = [
    "Microsoft Corporation", 
    "Google LLC", 
    "Adobe Systems", 
    "Oracle Corporation",
    "Nvidia Corporation",
    "SteelSeries ApS",
    "Valve Corporation"
]

# ------------------------------------------------
# JSON FILE HANDLING
# ------------------------------------------------
def create_json_file(file_name, default_data):
    """Create a JSON file if it doesn't exist, populating it with default_data."""
    if not os.path.exists(file_name):
        with open(file_name, "w") as file:
            json.dump(default_data, file, indent=4)

def setup_json_files():
    """Ensure whitelist and trusted developers JSON files exist."""
    create_json_file(WHITELIST_FILE, [])
    create_json_file(TRUSTED_DEVELOPERS_FILE, DEFAULT_TRUSTED_DEVELOPERS)

def load_json_file(file_name):
    """Load JSON data from the given file."""
    with open(file_name, "r") as file:
        return json.load(file)

def add_to_whitelist(name):
    """Add a process name to the whitelist."""
    whitelist = load_json_file(WHITELIST_FILE)
    if name not in whitelist:
        whitelist.append(name)
        with open(WHITELIST_FILE, "w") as file:
            json.dump(whitelist, file, indent=4)

def add_trusted_developer(developer):
    """Add a developer name to the trusted developers list."""
    trusted_devs = load_json_file(TRUSTED_DEVELOPERS_FILE)
    if developer not in trusted_devs:
        trusted_devs.append(developer)
        with open(TRUSTED_DEVELOPERS_FILE, "w") as file:
            json.dump(trusted_devs, file, indent=4)
        print(f"✅ Trusted Developer Added: {developer}")

# ------------------------------------------------
# DATABASE SETUP
# ------------------------------------------------
def setup_database():
    """Create or connect to the SQLite database and ensure required tables exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Table for real-time monitored processes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS processes (
            timestamp TEXT,
            pid INTEGER,
            name TEXT,
            path TEXT,
            suspicious INTEGER
        )
    ''')

    # Table for AI training data (optional)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS malware_features (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256 TEXT UNIQUE,
            feature_vector TEXT,
            label TEXT
        )
    ''')

    conn.commit()
    conn.close()

# ------------------------------------------------
# AI MODEL LOADING & PREDICTION
# ------------------------------------------------
def load_ai_model():
    """Load the trained AI model (if it exists)."""
    if os.path.exists(MODEL_FILE):
        print("🔮 Loading AI model from:", MODEL_FILE)
        return joblib.load(MODEL_FILE)
    else:
        print("⚠️ AI model file not found. The script will rely on manual checks only.")
        return None

def extract_process_features(pid):
    """
    Example function to gather runtime features for AI prediction.
    Expand or customize as needed.
    """
    try:
        proc = psutil.Process(pid)
        return {
            "cpu_usage": proc.cpu_percent(interval=0.1),
            "memory_usage": proc.memory_info().rss,
            "thread_count": proc.num_threads(),
            "open_files": len(proc.open_files()) if proc.open_files() else 0
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def ai_predict(model, features):
    """
    Use the AI model to predict if a process is 'malware' or 'benign'.
    Returns 'malware', 'benign', or 'unknown'.
    """
    if model is None:
        return "unknown"
    if features is None:
        return "unknown"

    # Convert features to a DataFrame with the same columns used in training
    df = pd.DataFrame([features], columns=FEATURE_COLUMNS)
    prediction = model.predict(df)[0]
    return "malware" if prediction == 1 else "benign"

# ------------------------------------------------
# FILE PUBLISHER & DISCORD NOTIFICATION
# ------------------------------------------------
def get_file_publisher(file_path):
    """Attempt to extract the publisher (CompanyName) from the file's version info."""
    try:
        info = win32api.GetFileVersionInfo(file_path, "\\StringFileInfo\\040904b0\\CompanyName")
        return info if info else "Unknown"
    except:
        return "Unknown"

def send_discord_notification(pid, name, path, reason):
    """
    Posts a message to your Discord channel using the webhook.
    Adjust the 'content' or embed structure as desired.
    """
    if not DISCORD_WEBHOOK_URL.startswith("https://discord.com/api/webhooks"):
        print("⚠️ Discord Webhook URL is not set correctly.")
        return

    message = (
        f"**Suspicious Process Detected**\n"
        f"Name: `{name}`\n"
        f"PID: `{pid}`\n"
        f"Path: `{path}`\n"
        f"Reason: {reason}\n"
    )

    payload = {"content": message}
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
        if response.status_code == 204:
            print("✅ Discord notification sent successfully.")
        else:
            print(f"⚠️ Failed to send Discord notification. Status code: {response.status_code}")
    except Exception as e:
        print(f"⚠️ Error sending Discord notification: {str(e)}")

# ------------------------------------------------
# GUI ALERT & PROCESS CONTROL
# ------------------------------------------------
def show_gui_alert(pid, name, path, reason):
    """Show a Tkinter popup asking the user to whitelist or terminate a suspicious process."""
    root = tk.Tk()
    root.withdraw()

    popup_message = (
        f"Process Name: {name}\n"
        f"PID: {pid}\n"
        f"File Path: {path}\n\n"
        f"⚠️ Reason: {reason}\n\n"
        "Would you like to whitelist this process?"
    )

    response = messagebox.askyesnocancel(
        "Suspicious Process Detected",
        popup_message
    )

    if response is None:
        print("🚫 No selection made. Ignoring.")
    elif response:
        add_to_whitelist(name)
        print(f"✅ Added {name} to whitelist.")
    else:
        kill_suspicious_process(pid, name, path)

    root.destroy()

def kill_suspicious_process(pid, name, path):
    """Terminate a suspicious process if possible."""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        print(f"❌ Process Terminated: {name} (PID: {pid}) - {path}")
    except psutil.NoSuchProcess:
        print(f"⚠️ Process already stopped: {name} (PID: {pid})")
    except psutil.AccessDenied:
        print(f"🚫 Access Denied: Unable to stop {name} (PID: {pid})")
    except Exception as e:
        print(f"⚠️ Error terminating {name} (PID: {pid}): {str(e)}")

# ------------------------------------------------
# TEST FUNCTION (Manual Trigger)
# ------------------------------------------------
def test_suspicious_process():
    """
    Manually triggers a 'suspicious process' event for testing.
    This will call the Discord notification and GUI alert,
    just like a real suspicious process.
    """
    pid = 9999
    name = "TestMalware.exe"
    path = "C:\\Users\\Public\\TestMalware.exe"
    reason = "Manual test: flagged as suspicious for demonstration."

    print("🚀 Running test_suspicious_process()...")

    # 1) Send Discord Notification
    send_discord_notification(pid, name, path, reason)

    # 2) Show GUI Alert
    show_gui_alert(pid, name, path, reason)

# ------------------------------------------------
# MAIN MONITOR FUNCTION
# ------------------------------------------------
def monitor_processes():
    """Continuously monitors running processes and flags suspicious activity."""
    setup_database()
    setup_json_files()
    ai_model = load_ai_model()

    logged_processes = set()

    while True:
        whitelist = load_json_file(WHITELIST_FILE)
        trusted_devs = load_json_file(TRUSTED_DEVELOPERS_FILE)

        for proc in psutil.process_iter(attrs=['pid', 'name', 'exe']):
            try:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                pid = proc.info['pid']
                name = proc.info['name']
                path = proc.info['exe'] if proc.info['exe'] else "Unknown"
                suspicious = 0
                reason = ""

                # Ignore system processes
                if name in SYSTEM_IGNORE_PROCESSES:
                    continue

                process_key = f"{name}-{pid}"
                if process_key in logged_processes:
                    continue

                # Manual Checks
                if any(path.startswith(dir) for dir in SUSPICIOUS_DIRS) and not any(path.startswith(dir) for dir in SAFE_DIRS):
                    suspicious = 1
                    reason = "Process is running from an unusual location."

                if name in SYSTEM_PROTECTED_FILES and not path.startswith("C:\\Windows\\System32\\"):
                    suspicious = 1
                    reason = f"System process {name} is running outside System32."

                if path == "Unknown":
                    suspicious = 1
                    reason = "Process has no valid executable path."

                # AI Check
                features = extract_process_features(pid)
                ai_result = ai_predict(ai_model, features)
                if ai_result == "malware":
                    suspicious = 1
                    if reason == "":
                        reason = "AI flagged this process as malware."

                # Trusted Developer
                publisher = get_file_publisher(path)
                if publisher in trusted_devs:
                    print(f"✅ Auto-authorized: {name} (PID: {pid}) - Signed by {publisher}")
                    logged_processes.add(process_key)
                    continue

                # Log to DB
                conn = sqlite3.connect(DB_NAME)
                cursor = conn.cursor()
                cursor.execute("INSERT INTO processes VALUES (?, ?, ?, ?, ?)",
                               (timestamp, pid, name, path, suspicious))
                conn.commit()
                conn.close()

                # If suspicious and not whitelisted, notify
                if suspicious and name.lower() not in whitelist:
                    print(f"⚠️ ALERT: Suspicious process detected! {name} (PID: {pid}) - {path} | Reason: {reason}")
                    
                    # 1) Send Discord Notification
                    send_discord_notification(pid, name, path, reason)
                    
                    # 2) Show GUI Alert
                    show_gui_alert(pid, name, path, reason)

                logged_processes.add(process_key)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        time.sleep(2)

# ------------------------------------------------
# ENTRY POINT
# ------------------------------------------------
if __name__ == "__main__":
    # If you run: python process_monitor.py test
    # It'll do a manual test. Otherwise, run normal monitoring.
    if len(sys.argv) > 1 and sys.argv[1].lower() == "test":
        test_suspicious_process()
    else:
        monitor_processes()
