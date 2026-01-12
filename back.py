from flask import Flask, request, jsonify
import json
import numpy as np
import joblib
import re
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import datetime
import os
from openai import OpenAI

# =====================================================
# APP INIT
# =====================================================
app = Flask(__name__)

# =====================================================
# OPENAI CONFIG
# =====================================================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY)

# =====================================================
# LOAD ML MODEL
# =====================================================
try:
    ml_model = joblib.load("svm_model.pkl")
    print("ML model loaded")
except Exception as e:
    print("ML model error:", e)
    ml_model = None

# =====================================================
# CLIENT AUTH
# =====================================================
AUTHORIZED_CLIENTS = {
    "demo-client-001": "ABC123SECRETKEY",
    "college-client-002": "XYZ789SECRETKEY"
}

def verify_client():
    cid = request.headers.get("X-CLIENT-ID")
    key = request.headers.get("X-API-KEY")

    if not cid or not key:
        return False, "Missing API credentials"

    if cid not in AUTHORIZED_CLIENTS:
        return False, "Invalid client ID"

    if AUTHORIZED_CLIENTS[cid] != key:
        return False, "Invalid API key"

    return True, cid

# =====================================================
# TIME HELPER
# =====================================================
def now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# =====================================================
# PCAP PARSER
# =====================================================
def parse_pcap(file):
    packets = rdpcap(file)
    logs = []
    for pkt in packets:
        if IP in pkt:
            port = None
            if TCP in pkt:
                port = int(pkt[TCP].dport)
            elif UDP in pkt:
                port = int(pkt[UDP].dport)

            logs.append({
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "port": port
            })
    return logs

# =====================================================
# SYSLOG PARSER (KALI)
# =====================================================
def parse_syslog(text):
    logs = []
    for line in text.split("\n"):
        m = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)", line)
        if m:
            logs.append({
                "src_ip": m.group(1),
                "dst_ip": "unknown",
                "port": int(m.group(2))
            })
    return logs

# =====================================================
# RULE-BASED DETECTION WITH MULTIPLE ATTACKS + SEVERITY
# =====================================================
def rule_based_detection(logs):
    ports = [l.get("port") for l in logs if l.get("port")]
    src_ips = [l["src_ip"] for l in logs]

    attacks = []

    # --- Port Scanning ---
    if len(set(ports)) >= 20 and len(logs) >= 40:
        attacks.append({
            "type": "Port Scanning",
            "severity": "Medium",
            "timestamp": now(),
            "details": f"{len(set(ports))} ports scanned"
        })

    # --- SSH Brute Force (Port 22) ---
    if ports.count(22) >= 8:
        attacks.append({
            "type": "SSH Brute Force",
            "severity": "High",
            "timestamp": now(),
            "details": f"{ports.count(22)} repeated SSH attempts"
        })

    # --- RDP Brute Force (Port 3389) ---
    if ports.count(3389) >= 8:
        attacks.append({
            "type": "RDP Brute Force",
            "severity": "High",
            "timestamp": now(),
            "details": f"{ports.count(3389)} failed RDP attempts"
        })

    # --- DoS Attack ---
    if len(logs) >= 150:
        attacks.append({
            "type": "DoS Attack",
            "severity": "High",
            "timestamp": now(),
            "details": f"{len(logs)} requests in short time"
        })

    # --- DDoS Attack ---
    if len(set(src_ips)) >= 10:
        attacks.append({
            "type": "DDoS Attack",
            "severity": "Critical",
            "timestamp": now(),
            "details": f"Traffic from {len(set(src_ips))} unique IPs"
        })

    if not attacks:
        attacks.append({
            "type": "Normal Traffic",
            "severity": "Low",
            "timestamp": now(),
            "details": "No attacks detected"
        })

    return attacks

# =====================================================
# ML DETECTION
# =====================================================
def ml_detection(logs):
    if not ml_model:
        return {
            "type": "ML Model",
            "severity": "Low",
            "timestamp": now(),
            "details": "ML model unavailable"
        }

    features = np.array([
        len(logs),
        len(set(l["src_ip"] for l in logs)),
        len(set(l["port"] for l in logs if l.get("port")))
    ]).reshape(1, -1)

    prediction = int(ml_model.predict(features)[0])
    is_attack = (prediction == -1)

    return {
        "type": "ML Anomaly Detection",
        "severity": "Medium" if is_attack else "Low",
        "timestamp": now(),
        "details": "Anomalous traffic detected" if is_attack else "ML normal"
    }

# =====================================================
# OPENAI EXPLANATION
# =====================================================
def openai_explain(logs, types):
    try:
        prompt = f"""
        You are a cybersecurity expert.
        Logs:
        {json.dumps(logs[:10], indent=2)}

        Detected attacks: {types}

        Explain these attacks simply.
        """

        response = client.chat.completions.create(
            model="o4-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst."},
                {"role": "user", "content": prompt}
            ]
        )

        return response.choices[0].message["content"]

    except Exception as e:
        print("OpenAI ERROR:", e)
        return "AI explanation unavailable."

# =====================================================
# PIPELINE
# =====================================================
def run_detection_pipeline(logs):
    attacks = rule_based_detection(logs)

    ml_result = ml_detection(logs)
    attacks.append(ml_result)

    print("\n===== ALERTS GENERATED =====")
    for a in attacks:
        print(a)

    explanation = openai_explain(logs, ", ".join(a["type"] for a in attacks))

    return {
        "detected": any(a["type"] != "Normal Traffic" for a in attacks),
        "attacks": attacks,
        "explanation": explanation
    }

# =====================================================
# API ENDPOINT
# =====================================================
@app.route("/analyze", methods=["POST"])
def analyze_api():
    ok, cid = verify_client()
    if not ok:
        return jsonify({"error": cid}), 401

    logs = request.get_json(silent=True)

    if not logs and "pcap" in request.files:
        logs = parse_pcap(request.files["pcap"])

    if not logs and request.form.get("syslog"):
        logs = parse_syslog(request.form["syslog"])

    if not logs:
        return jsonify({"error": "No logs received"}), 400

    result = run_detection_pipeline(logs)

    return jsonify({
        "status": "success",
        "client_id": cid,
        "result": result
    })

# =====================================================
# RUN FLASK
# =====================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

