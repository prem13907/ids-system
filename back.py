from flask import Flask, request, jsonify
import json
import numpy as np
import joblib
import re
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import os
from openai import OpenAI

# ==============================
# APP INIT
# ==============================
app = Flask(__name__)

# ==============================
# CONFIG
# ==============================
OPENAI_API_KEY = os.getenv("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")
client = OpenAI(api_key=OPENAI_API_KEY)

# Load ML model
try:
    ml_model = joblib.load("svm_model.pkl")
except Exception as e:
    print("ML model load error:", e)
    ml_model = None

# ==============================
# AUTHORIZED CLIENTS
# ==============================
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
        return False, "Invalid Client ID"

    if AUTHORIZED_CLIENTS[cid] != key:
        return False, "Invalid API Key"

    return True, cid

# ==============================
# LOG PARSERS
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
            logs.append(entry)

    return logs

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

# ==============================
# RULE-BASED DETECTION
# ==============================
def rule_based_detection(logs):
    ports = [l["port"] for l in logs if l.get("port")]
    src_ips = [l["src_ip"] for l in logs]

    if len(set(ports)) >= 4:
        return True, "Port Scanning Detected"

    if ports.count(22) > 6:
        return True, "Brute Force Attack Detected"

    if len(logs) > 25 and len(set(src_ips)) > 12:
        return True, "Possible DDoS Attack"

    return False, "Normal Traffic"

# ==============================
# ML DETECTION
# ==============================
def ml_detection(logs):
    if not ml_model:
        return False, "ML model unavailable"

    features = np.array([
        len(logs),
        len(set(l["src_ip"] for l in logs)),
        len(set(l["port"] for l in logs if l.get("port")))
    ]).reshape(1, -1)

    prediction = int(ml_model.predict(features)[0])
    return (prediction == -1), "ML-based Anomaly Detection"

# ==============================
# OPENAI EXPLANATION
# ==============================
def openai_explain(logs, summary):
    try:
        prompt = f"""
        You are a cybersecurity expert.
        Here are sample logs:
        {json.dumps(logs[:10], indent=2)}

        Detection Summary: {summary}

        Explain the attack clearly in simple terms.
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
        print("OpenAI Error:", e)
        return "AI explanation unavailable."

# ==============================
# DETECTION PIPELINE
# ==============================
def run_detection_pipeline(logs):
    rule_hit, rule_msg = rule_based_detection(logs)
    ml_hit, ml_msg = ml_detection(logs)
    detected = rule_hit or ml_hit
    summary = rule_msg if rule_hit else ml_msg
    explanation = openai_explain(logs, summary)

    return {
        "detected": bool(detected),
        "summary": summary,
        "explanation": explanation
    }

# ==============================
# API ENDPOINT
# ==============================
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
