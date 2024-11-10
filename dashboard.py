from flask import Flask, render_template, request, json
from logging_config import log_attack  

app = Flask(__name__)

alerts = []

@app.route("/")
def home():
   
    return render_template("dashboard.html", alerts=alerts)

@app.route("/add_alert/<alert_message>", methods=['GET'])
def add_alert(alert_message):
    alerts.append(alert_message)
    log_attack(alert_message)
    return json.dumps({'status': 'success', 'message': f'Alert added: {alert_message}'}), 200

def start_dashboard():
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    start_dashboard()
