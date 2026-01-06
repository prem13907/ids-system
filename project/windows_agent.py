import psutil
import socket
import requests
import time
import json

# =========================
# CONFIG
# =========================
SERVER_URL = "http://127.0.0.1:5000/analyze"



CLIENT_ID = "demo-client-001"
API_KEY = "ABC123SECRETKEY"

HEADERS = {
    "X-CLIENT-ID": CLIENT_ID,
    "X-API-KEY": API_KEY,
    "Content-Type": "application/json"
}

# =========================
# PERMISSION PROMPT
# =========================
def ask_permission():
    print("⚠ Network Monitoring Permission Required")
    consent = input("Allow network monitoring? (yes/no): ").lower()
    return consent == "yes"

# =========================
# LOG CAPTURE (NO WIRESHARK)
# =========================
def capture_network_logs():
    logs = []
    connections = psutil.net_connections(kind="inet")

    for conn in connections:
        if conn.raddr:
            logs.append({
                "src_ip": socket.gethostbyname(socket.gethostname()),
                "dst_ip": conn.raddr.ip,
                "port": conn.raddr.port
            })

    return logs

# =========================
# SEND TO SERVER
# =========================
def send_logs(logs):
    try:
        response = requests.post(
            SERVER_URL,
            headers=HEADERS,
            json=logs,
            timeout=10
        )
        print("Server Response:", response.json())
    except Exception as e:
        print("Error sending logs:", e)

# =========================
# MAIN LOOP
# =========================
def main():
    if not ask_permission():
        print("Permission denied. Exiting.")
        return

    print("✅ Monitoring started...")
    while True:
        logs = capture_network_logs()
        if logs:
            send_logs(logs)
        time.sleep(10)  # send every 10 seconds

if __name__ == "__main__":
    main()
