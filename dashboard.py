from flask import Flask, render_template, request, json
from logging_config import log_attack  # Assuming this is correctly set up for logging

app = Flask(__name__)

# List to hold alerts
alerts = []

@app.route("/")
def home():
    # Render the dashboard template and pass in the alerts
    return render_template("dashboard.html", alerts=alerts)

@app.route("/add_alert/<alert_message>", methods=['GET'])
def add_alert(alert_message):
    # Add the alert message to the alerts list
    alerts.append(alert_message)
    # Log the alert (you can also send an email here if needed)
    log_attack(alert_message)
    return json.dumps({'status': 'success', 'message': f'Alert added: {alert_message}'}), 200

def start_dashboard():
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    # Run the Flask app in debug mode for development
    start_dashboard()
