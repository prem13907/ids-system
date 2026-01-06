from flask import Flask, request, jsonify
import json
import re
import numpy as np
import joblib
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import google.generativeai as genai

# ==============================
# APP INIT
# ==============================
app = Flask(__name__)

# ==============================
# CONFIG
# ==============================
GEMINI_API_KEY = "AIzaSyDnCD4-n8GPvcl6NNLVwbjpp_zomjELAK8"
genai.configure(api_key=GEMINI_API_KEY)

# Load ML model
try:
    ml_model = joblib.load("svm_model.pkl")
except Exception as e:
    print("ML model not loaded:", e)
    ml_model = None

# ==============================
# CLIENT AUTHORIZATION KEYS
# ==============================
AUTHORIZED_CLIENTS = {
    "demo-client-001": "ABC123SECRETKEY",
    "college-client-002": "XYZ789SECRETKEY"
}

# ==============================
# CLIENT VERIFICATION
# ==============================
def verify_client():
    client_id = request.headers.get("X-CLIENT-ID")
    api_key = request.headers.get("X-API-KEY")

    if not client_id or not api_key:
        return False, "Missing authentication headers"

    if client_id not in AUTHORIZED_CLIENTS:
        return False, "Invalid client ID"

    if AUTHORIZED_CLIENTS[client_id] != api_key:
        return False, "Invalid API key"

    return True, client_id

# ==============================
# CLIENT IP FETCH
# ==============================
def get_client_ip():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if ip:
        ip = ip.split(",")[0].strip()
    return ip

# ==============================
# PCAP PARSER
# ==============================
def parse_pcap(file):
    packets = rdpcap(file)
    logs = []

    for pkt in packets:
        if IP in pkt:
            entry = {
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "port": None
            }

            if TCP in pkt:
                entry["port"] = int(pkt[TCP].dport)
            elif UDP in pkt:
                entry["port"] = int(pkt[UDP].dport)
            else:
                continue

            logs.append(entry)

    return logs

# ==============================
# SYSLOG PARSER
# ==============================
def parse_syslog(raw_text):
    logs = []
    for line in raw_text.split("\n"):
        match = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)", line)
        if match:
            logs.append({
                "src_ip": match.group(1),
                "dst_ip": "unknown",
                "port": int(match.group(2))
            })
    return logs

# ==============================
# RULE-BASED DETECTION
# ==============================
def rule_based_detection(logs):
    ports = [l["port"] for l in logs if l.get("port") is not None]
    src_ips = [l["src_ip"] for l in logs]

    if len(set(ports)) >= 4:
        return True, "Port Scanning Detected"

    if ports.count(22) > 6:
        return True, "Brute Force Attack Detected"

    if len(logs) > 20 and len(set(src_ips)) > 10:
        return True, "Possible DDoS Attack"

    return False, "Normal Traffic"

# ==============================
# ML DETECTION (SVM)
# ==============================
def ml_detection(logs):
    if not ml_model or not logs:
        return False, "ML model unavailable"

    features = np.array([
        len(logs),
        len(set(l["src_ip"] for l in logs)),
        len(set(l["port"] for l in logs if l.get("port") is not None))
    ]).reshape(1, -1)

    prediction = int(ml_model.predict(features)[0])
    is_attack = True if prediction == -1 else False

    return is_attack, "ML-based Anomaly Detection"

# ==============================
# GEMINI AI EXPLANATION
# ==============================
def gemini_explain(logs, summary):
    try:
        model = genai.GenerativeModel("gemini-pro")


        prompt = f"""
        You are a cybersecurity analyst.
        Below are sample network logs:
        {json.dumps(logs[:10], indent=2)}

        Detection Summary:
        {summary}

        Explain the attack and its security impact in simple terms.
        """

        response = model.generate_content(prompt)
        return response.text

    except Exception as e:
        print("Gemini Error:", e)
        return "AI explanation unavailable. Detection based on rule-based and ML analysis."

# ==============================
# DETECTION PIPELINE
# ==============================
def run_detection_pipeline(logs):
    rule_hit, rule_msg = rule_based_detection(logs)
    ml_hit, ml_msg = ml_detection(logs)

    detected = bool(rule_hit or ml_hit)
    summary = rule_msg if rule_hit else ml_msg

    explanation = gemini_explain(logs, summary)

    return {
        "detected": detected,
        "summary": summary,
        "explanation": explanation
    }

# ==============================
# API ENDPOINT
# ==============================
@app.route("/analyze", methods=["POST"])
def analyze_api():
    # ----------------------
    # VERIFY CLIENT
    # ----------------------
    authorized, client_or_error = verify_client()
    if not authorized:
        return jsonify({"error": client_or_error}), 401

    client_id = client_or_error
    client_ip = get_client_ip()

    # ----------------------
    # PARSE LOGS
    # ----------------------
    logs = request.get_json(silent=True)

    # PCAP upload
    if not logs and "pcap" in request.files:
        logs = parse_pcap(request.files["pcap"])

    # Syslog input
    if not logs and request.form.get("syslog"):
        logs = parse_syslog(request.form.get("syslog"))

    if not logs:
        return jsonify({"error": "No logs received"}), 400

    # Attach client info to logs
    for log in logs:
        log["client_ip"] = client_ip
        log["client_id"] = client_id

    result = run_detection_pipeline(logs)

    return jsonify({
        "status": "success",
        "client_id": client_id,
        "client_ip": client_ip,
        "result": result
    })

# ==============================
# RUN APP
# ==============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
