import time
import requests

API_URL = "http://127.0.0.1:8000/api/v1/ingest"
ATTACKER_IP = "103.45.67.89"
BENIGN_IP = "192.168.1.15"

scenario = [
    # 1. Normal user traffic (Ignored)
    {
        "source_ip": BENIGN_IP,
        "user": "emp_rahul",
        "endpoint": "/dashboard/overview",
        "event_type": "NORMAL_TRAFFIC",
        "payload_bytes": 410,
        "req_rate": 8.0,
        "sensitivity": 1,
        "status_code": 200
    },
    # 2. Stage 1: Attacker fails login (Looks like a harmless error initially)
    {
        "source_ip": ATTACKER_IP,
        "user": "admin",
        "endpoint": "/api/auth/login",
        "event_type": "AUTH_FAILURE",
        "payload_bytes": 620,
        "req_rate": 28.0,
        "sensitivity": 4,
        "status_code": 401
    },
    # 3. Stage 2: Attacker escalates privilege via forged token
    {
        "source_ip": ATTACKER_IP,
        "user": "admin",
        "endpoint": "/api/iam/sudo-token",
        "event_type": "PRIV_ESC",
        "payload_bytes": 2400,
        "req_rate": 42.0,
        "sensitivity": 8,
        "status_code": 200
    },
    # 4. Stage 3: Attacker moves laterally to internal subnet
    {
        "source_ip": ATTACKER_IP,
        "user": "sys_daemon",
        "endpoint": "/internal/v1/vault-keys",
        "event_type": "INTERNAL_PIVOT",
        "payload_bytes": 8900,
        "req_rate": 65.0,
        "sensitivity": 9,
        "status_code": 200
    },
    # 5. Stage 4: Attacker dumps production database (Chori)
    {
        "source_ip": ATTACKER_IP,
        "user": "sys_daemon",
        "endpoint": "/db/backup/users_dump.csv",
        "event_type": "DB_DUMP",
        "payload_bytes": 1250000,
        "req_rate": 95.0,
        "sensitivity": 10,
        "status_code": 200
    }
]

if __name__ == "__main__":
    print("Starting live telemetry stream to Sentinel Engine...")
    for idx, event in enumerate(scenario, 1):
        resp = requests.post(API_URL, json=event)
        print(f"[Step {idx}] Sent {event['event_type']} from {event['source_ip']} -> Response: {resp.json()}")
        time.sleep(2.0)