from collections import defaultdict
import time
import requests
from scapy.all import *
from logging_config import log_attack, log_anomaly
from scapy.all import sniff
from models import *  
from alerting import send_email_alert
from dashboard import start_dashboard
import logging  

OUTBOUND_CONNECTION_THRESHOLD = 50
TIME_WINDOW = 60
arp_table = {}
known_cnc_ips = {"192.168.100.10", "10.20.30.40"}
known_dns_ips = {"example.com": "93.184.216.34"}
ip_packet_counts = defaultdict(lambda: {'count': 0, 'timestamp': time.time()})
connection_tracker = defaultdict(list)

def send_to_dashboard(alert_message):
    try:
        url = "http://localhost:5000/add_alert/"
        requests.get(url + alert_message)
    except Exception as e:
        logging.error(f"Error sending alert to dashboard: {e}")

def extract_features(packet):
    features = {
        "packet_length": len(packet),
        "src_ip": packet[IP].src if packet.haslayer(IP) else "N/A",
        "dst_ip": packet[IP].dst if packet.haslayer(IP) else "N/A",
        "protocol": packet.proto
    }
    return features

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_time = time.time()

        if packet_time - ip_packet_counts[src_ip]['timestamp'] < 10:
            ip_packet_counts[src_ip]['count'] += 1
            if ip_packet_counts[src_ip]['count'] > 100:
                logging.info(f"[ALERT] High traffic volume from {src_ip}")
        else:
            ip_packet_counts[src_ip] = {'count': 1, 'timestamp': packet_time}

        if packet.haslayer(TCP):
            if packet[TCP].flags == "S":
                logging.info(f"[ALERT] Potential SYN flood detected from {src_ip} to {dst_ip}")

        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Payload Size: {len(packet)} bytes")

        detect_mitm(packet)
        detect_ip_spoofing(packet)
        detect_dns_spoofing(packet)
        detect_botnet(packet)

        alert_message = f"Possible Attack detected from IP {src_ip}"
        send_to_dashboard(alert_message)

        if detect_botnet(packet) or detect_mitm(packet):
            send_email_alert(f"Attack Alert: {alert_message}")

def main():
    print("Starting network monitoring...\n")
    sniff(filter="tcp port 80 or tcp port 443 or tcp port 8080", prn=packet_callback, store=0)
    start_dashboard()

if __name__ == "__main__":
    main()
