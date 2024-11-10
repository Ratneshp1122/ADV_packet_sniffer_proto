import time
import logging
import numpy as np
from scapy.all import *
from sklearn.ensemble import IsolationForest

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

OUTBOUND_CONNECTION_THRESHOLD = 50
TIME_WINDOW = 60
arp_table = {}
known_cnc_ips = {"192.168.100.10", "10.20.30.40"} 
known_dns_ips = {"example.com": "93.184.216.34"}  
ip_packet_counts = defaultdict(lambda: {'count': 0, 'timestamp': time.time()})
connection_tracker = defaultdict(list)
target_ips = ["192.168.100.10", "10.20.30.40"]

model = IsolationForest()

packet_features = []


def extract_features(packet):
    features = {
        "packet_length": len(packet),
        "src_ip": packet[IP].src if packet.haslayer(IP) else "N/A",
        "dst_ip": packet[IP].dst if packet.haslayer(IP) else "N/A",
        "protocol": packet.proto
    }
    return features


def detect_anomaly(packet):
    global packet_features
    features = np.array([list(extract_features(packet).values())]).reshape(1, -1)
    packet_features.append(features)

    if len(packet_features) > 100:  
        features_batch = np.vstack(packet_features)
        anomaly_scores = model.fit_predict(features_batch)
        if anomaly_scores[-1] == -1: 
            logging.info(f"Anomaly detected from {packet[IP].src}")

        packet_features = [] 


def detect_mitm(packet):
    if ARP in packet and packet[ARP].op == 2:  
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        if src_ip in arp_table:
            if arp_table[src_ip] != src_mac:
                logging.info(f"[ALERT] MITM detected: {src_ip} has changed MAC from {arp_table[src_ip]} to {src_mac}")
        arp_table[src_ip] = src_mac


def detect_ip_spoofing(packet):
    if IP in packet:
        if packet[IP].ttl < 30:  
            logging.info(f"[ALERT] Suspicious IP spoofing detected: {packet[IP].src} with TTL={packet[IP].ttl}")


def detect_dns_spoofing(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 1:
        domain = packet[DNS].qd.qname.decode()
        if packet.haslayer(DNSRR):
            resolved_ip = packet[DNSRR].rdata
            if domain in known_dns_ips and resolved_ip != known_dns_ips[domain]:
                logging.info(
                    f"[ALERT] DNS Spoofing detected for {domain}: got {resolved_ip}, expected {known_dns_ips[domain]}")


def simulate_botnet_traffic(target_ips, duration=10, connections_per_ip=100):
    start_time = time.time()
    while time.time() - start_time < duration:
        for ip in target_ips:
            packet = IP(dst=ip) / TCP(dport=80, flags="S")
            send(packet, verbose=0)
            time.sleep(0.01)
    print("Botnet simulation complete.")


def detect_botnet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = time.time()

        connection_tracker[src_ip].append(current_time)
        connection_tracker[src_ip] = [timestamp for timestamp in connection_tracker[src_ip] if
                                      current_time - timestamp < TIME_WINDOW]

        if len(connection_tracker[src_ip]) > OUTBOUND_CONNECTION_THRESHOLD:
            logging.info(
                f"[ALERT] Botnet behavior detected: {src_ip} -> {dst_ip} with {len(connection_tracker[src_ip])} connections in {TIME_WINDOW} seconds")

        if dst_ip in known_cnc_ips:
            logging.info(f"[ALERT] Connection to known C&C server detected: {src_ip} -> {dst_ip}")


def detect_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        logging.info(f"[ALERT] Potential SYN flood detected from {src_ip} to {dst_ip}")
