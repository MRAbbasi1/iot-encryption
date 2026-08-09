import sqlite3
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import init_db, get_connection
from security import decrypt_iot_payload

init_db()

app = FastAPI()

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=get_client_ip)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SecurePayload(BaseModel):
    iv: str
    ciphertext: str
    tag: str

@app.post("/api/iot-data")
@limiter.limit("30/minute")
async def receive_iot_data(request: Request, payload: SecurePayload):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        sensor_data = decrypt_iot_payload(payload.iv, payload.ciphertext, payload.tag)

        device_id = sensor_data.get("device_id")
        if not device_id:
            raise HTTPException(status_code=400, detail="device_id missing in decrypted payload")

        cursor.execute("SELECT is_active FROM devices WHERE device_id = ?", (device_id,))
        device_row = cursor.fetchone()

        if not device_row:
            raise HTTPException(status_code=403, detail="Device not registered")

        if device_row[0] == 0:
            raise HTTPException(status_code=403, detail="Device is blocked")

        current_time = int(time.time())
        device_time = sensor_data.get('timestamp')

        if device_time is None:
            raise HTTPException(status_code=400, detail="timestamp missing in decrypted payload")

        if abs(current_time - device_time) > 300:
            raise HTTPException(status_code=400, detail="Timestamp out of acceptable window")

        cursor.execute('''
            INSERT INTO sensor_data (device_id, temperature, humidity, pressure, timestamp, received_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            device_id,
            sensor_data['temperature'],
            sensor_data['humidity'],
            sensor_data['pressure'],
            device_time,
            current_time
        ))
        conn.commit()

        return {"status": "success", "message": "Data saved."}

    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Duplicate packet")
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    finally:
        conn.close()

@app.get("/api/iot-data")
@limiter.limit("60/minute")
async def get_iot_data(request: Request, limit: int = 20):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT device_id, temperature, humidity, pressure, timestamp, received_at
            FROM sensor_data
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))

        rows = cursor.fetchall()

        data = []
        for row in rows:
            data.append({
                "device_id": row[0],
                "temperature": row[1],
                "humidity": row[2],
                "pressure": row[3],
                "timestamp": row[4],
                "received_at": row[5]
            })

        return {"status": "success", "data": data}

    finally:
        conn.close()