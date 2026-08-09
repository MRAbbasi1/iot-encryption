import os
import sqlite3

DB_FILE = os.getenv("DB_FILE", "data/iot_data.db")
os.makedirs(os.path.dirname(DB_FILE) if os.path.dirname(DB_FILE) else '.', exist_ok=True)

def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            is_active INTEGER NOT NULL CHECK (is_active IN (0, 1))
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sensor_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            temperature REAL,
            humidity REAL,
            pressure REAL,
            timestamp INTEGER,
            received_at INTEGER,
            FOREIGN KEY (device_id) REFERENCES devices(device_id),
            UNIQUE(device_id, timestamp)
        )
    ''')
    conn.commit()
    conn.close()