from flask import Flask, request
import json
from google import genai

# ==============================
# CONFIG
# ==============================
API_KEY = "AIzaSyAGD36jGfoV0v3eP4kbkRbYfs-CqdA1mu4"
client = genai.Client(api_key=API_KEY)

app = Flask(__name__)

# ==============================
# GEMINI ANALYSIS
# ==============================
def analyze_with_gemini(logs):
    prompt = f"""
You are a cybersecurity analyst.

Analyze the following network traffic logs and identify:
1. Attack Type
2. Risk Level (Low / Medium / High)
3. Explanation

Network Logs:
{json.dumps(logs, indent=2)}
"""

    response = client.models.generate_content(
        model="gemini-1.5-pro",   # ✅ FIXED MODEL NAME
        contents=prompt
    )

    return response.text

# ==============================
# ROUTE
# ==============================
@app.route("/", methods=["GET", "POST"])
def index():
    result_html = ""

    if request.method == "POST":
        log_text = request.form.get("logs")

        try:
            logs = json.loads(log_text)
            ai_response = analyze_with_gemini(logs)

            result_html = f"""
            <div class="box">
                <h3>📊 Detection Result</h3>
                <p><b>Status:</b> Analysis Completed</p>
                <h3>🤖 Gemini AI Explanation</h3>
                <pre>{ai_response}</pre>
            </div>
            """
        except json.JSONDecodeError:
            result_html = """
            <div class="box error">
                <b>Invalid JSON format.</b>
            </div>
            """
        except Exception as e:
            result_html = f"""
            <div class="box error">
                <b>Gemini Error:</b><br>{str(e)}
            </div>
            """

    return f"""
<!DOCTYPE html>
<html>
<head>
<title>AI Network Intrusion Analyzer</title>
<style>
body {{
    background:#020617;
    color:white;
    font-family:Arial;
    padding:30px;
}}
textarea {{
    width:100%;
    height:200px;
    font-family:monospace;
}}
button {{
    padding:10px 20px;
    margin-top:10px;
}}
.box {{
    margin-top:30px;
    padding:20px;
    background:#020617;
    border:1px solid #38bdf8;
    border-radius:10px;
}}
.error {{
    border-color:red;
    color:#f87171;
}}
pre {{
    white-space:pre-wrap;
}}
</style>
</head>

<body>
<h1>🔐 AI-Based Network Intrusion & Suspicious Traffic Analyzer</h1>

<form method="POST">
<p>Paste Network Logs (JSON format):</p>
<textarea name="logs">[
  {{
    "src_ip": "45.33.32.156",
    "port": 21
  }},
  {{
    "src_ip": "45.33.32.156",
    "port": 22
  }},
  {{
    "src_ip": "45.33.32.156",
    "port": 23
  }}
]</textarea><br>
<button type="submit">Analyze Traffic</button>
</form>

{result_html}

</body>
</html>
"""

# ==============================
# RUN
# ========
