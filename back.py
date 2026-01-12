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
    ports = [l.get("dst_port") for l in logs if l.get("dst_port")]
    src_ips = [l.get("src_ip") for l in logs if l.get("src_ip")]
    unique_ports = set(ports)
    unique_ips = set(src_ips)

    results = []

    # 1️⃣ PORT SCAN — very easy to trigger
    if len(unique_ports) >= 10:
        results.append({
            "type": "Port Scan",
            "severity": "Medium",
            "timestamp": now(),
            "details": f"{len(unique_ports)} unique ports targeted"
        })

    # 2️⃣ SSH BRUTE FORCE (port 22)
    if ports.count(22) >= 5:
        results.append({
            "type": "SSH Brute Force",
            "severity": "High",
            "timestamp": now(),
            "details": f"{ports.count(22)} attempts to SSH"
        })

    # 3️⃣ RDP BRUTE FORCE (port 3389)
    if ports.count(3389) >= 5:
        results.append({
            "type": "RDP Brute Force",
            "severity": "High",
            "timestamp": now(),
            "details": f"{ports.count(3389)} attempts to RDP"
        })

    # 4️⃣ DOS ATTACK
    if len(logs) >= 120:
        results.append({
            "type": "DoS Attack",
            "severity": "High",
            "timestamp": now(),
            "details": f"{len(logs)} connections in short time"
        })

    # 5️⃣ DDOS (many unique IPs)
    if len(unique_ips) >= 8:
        results.append({
            "type": "DDoS Attack",
            "severity": "Critical",
            "timestamp": now(),
            "details": f"Traffic from {len(unique_ips)} unique IPs"
        })

    return results

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
    try:
        # First try JSON body (Windows agent)
        if request.is_json:
            data = request.get_json()
            logs = data.get("logs", [])
        else:
            # Legacy syslog fallback
            if "syslog" in request.form:
                logs = parse_syslog(request.form["syslog"])
            else:
                return jsonify({"error": "No logs received"}), 400

        if not isinstance(logs, list):
            return jsonify({"error": "Logs must be a list"}), 400

        # Ensure all logs are dictionaries
        clean_logs = []
        for l in logs:
            if isinstance(l, str):
                try:
                    l = json.loads(l)
                except:
                    continue
            clean_logs.append(l)

        if not clean_logs:
            return jsonify({"error": "No valid logs"}), 400

        result = run_detection_pipeline(clean_logs)

        return jsonify({
            "status": "success",
            "client_id": request.headers.get("X-CLIENT-ID"),
            "result": result
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =====================================================
# RUN FLASK
# =====================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

