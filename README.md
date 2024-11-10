# ADV IDS/IPS Packet Sniffer

## Project Description

The **ADV IDS/IPS Packet Sniffer** is an advanced network monitoring tool designed to enhance network security by detecting various cyber threats in real-time. It functions as both an Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) by capturing and analyzing network packets to identify malicious activities such as Man-in-the-Middle (MITM) attacks, IP spoofing, SYN floods, botnets, and DNS spoofing.

This tool leverages both traditional and machine learning-based techniques for anomaly detection. By inspecting incoming network traffic, it detects patterns indicative of potential attacks, raises alerts, and even sends email notifications for immediate response. Additionally, it integrates with a live web dashboard to display alerts, helping security personnel monitor threats in real-time.

## Key Features

- **Real-Time Packet Capture**: Captures network packets using Scapy, providing detailed information such as source and destination IPs, payload size, and protocol.
- **Anomaly Detection**: Uses **Isolation Forest** from `sklearn.ensemble` to detect unusual patterns or behaviors within network traffic.
- **Intrusion Detection**: Detects a range of attacks including:
  - **MITM (Man-in-the-Middle)** attacks via ARP spoofing.
  - **IP Spoofing** based on abnormal TTL values.
  - **SYN Floods**, which overwhelm servers with connection requests.
  - **Botnet Behavior** by analyzing unusual outbound connections.
  - **DNS Spoofing**, detecting mismatches between expected and resolved DNS IPs.
- **Alert System**: Sends alerts to a live web dashboard and via email, helping network administrators respond to threats quickly.
- **Logging and Reporting**: Logs all detected anomalies and attacks into log files for later analysis and audit.

## Technologies Used

- **Scapy**: For packet sniffing and manipulation.
- **Python**: For core functionality and integrating machine learning models.
- **Isolation Forest**: A machine learning algorithm for anomaly detection.
- **Flask**: To create a live web dashboard for real-time monitoring.
- **smtplib**: To send email alerts.
- **Logging**: For tracking detected events and system activity.

## Installation

1. Clone the repository.
2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up SMTP credentials for email alerts.
4. Run the `main.py` script to start monitoring.

## Use Case

Ideal for security professionals and system administrators who need to monitor their networks for security breaches or unusual behavior. It can be used to proactively secure networks by identifying vulnerabilities before they are exploited.

This project is a step toward creating more efficient, automated, and intelligent network security systems.
