"""
Intrusion Detection System (IDS)
Main application with real-time network monitoring and ML-based threat detection
"""

import os
import sys
import json
import logging
from datetime import datetime
from collections import defaultdict
import threading
import time

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import pickle
except ImportError as e:
    print(f"Error: Missing required package - {e}")
    print("\nPlease install required packages:")
    print("pip install scapy numpy pandas scikit-learn")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ids_logs.log'),
        logging.StreamHandler()
    ]
)

class IntrusionDetectionSystem:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_count = 0
        self.alerts = []
        self.traffic_stats = defaultdict(lambda: {
            'packet_count': 0,
            'bytes_sent': 0,
            'tcp_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'suspicious_flags': 0
        })
        
        # Initialize ML model for anomaly detection
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Port scan detection
        self.port_scan_threshold = 20  # Number of different ports in short time
        self.port_scan_window = {}  # {ip: [(port, timestamp)]}
        
        # DDoS detection
        self.ddos_threshold = 100  # Packets per second from same IP
        self.ddos_window = {}  # {ip: [(timestamp)]}
        
        self.running = False
        
    def extract_features(self, packet):
        """Extract features from packet for ML analysis"""
        features = {
            'packet_size': len(packet),
            'has_tcp': int(packet.haslayer(TCP)),
            'has_udp': int(packet.haslayer(UDP)),
            'has_icmp': int(packet.haslayer(ICMP)),
            'tcp_flags': 0,
            'src_port': 0,
            'dst_port': 0,
            'protocol': 0
        }
        
        if packet.haslayer(IP):
            features['protocol'] = packet[IP].proto
            
        if packet.haslayer(TCP):
            features['tcp_flags'] = int(packet[TCP].flags)
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            
        if packet.haslayer(UDP):
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport
            
        return features
    
    def detect_port_scan(self, src_ip, dst_port):
        """Detect port scanning attempts"""
        current_time = time.time()
        
        if src_ip not in self.port_scan_window:
            self.port_scan_window[src_ip] = []
        
        # Add current port access
        self.port_scan_window[src_ip].append((dst_port, current_time))
        
        # Remove old entries (older than 10 seconds)
        self.port_scan_window[src_ip] = [
            (port, ts) for port, ts in self.port_scan_window[src_ip]
            if current_time - ts < 10
        ]
        
        # Check if threshold exceeded
        unique_ports = len(set(port for port, _ in self.port_scan_window[src_ip]))
        if unique_ports > self.port_scan_threshold:
            return True
        return False
    
    def detect_ddos(self, src_ip):
        """Detect DDoS attempts"""
        current_time = time.time()
        
        if src_ip not in self.ddos_window:
            self.ddos_window[src_ip] = []
        
        # Add current packet timestamp
        self.ddos_window[src_ip].append(current_time)
        
        # Remove old entries (older than 1 second)
        self.ddos_window[src_ip] = [
            ts for ts in self.ddos_window[src_ip]
            if current_time - ts < 1
        ]
        
        # Check if threshold exceeded
        if len(self.ddos_window[src_ip]) > self.ddos_threshold:
            return True
        return False
    
    def detect_suspicious_flags(self, packet):
        """Detect suspicious TCP flag combinations"""
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            # Check for NULL scan (no flags)
            if flags == 0:
                return "NULL Scan Detected"
            # Check for XMAS scan (FIN, PSH, URG)
            if flags & 0x29 == 0x29:
                return "XMAS Scan Detected"
            # Check for SYN-FIN (invalid combination)
            if flags & 0x03 == 0x03:
                return "SYN-FIN Attack Detected"
        return None
    
    def generate_alert(self, alert_type, severity, details):
        """Generate security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'details': details
        }
        self.alerts.append(alert)
        
        # Log alert
        log_msg = f"[{severity}] {alert_type}: {details}"
        if severity == "CRITICAL":
            logging.critical(log_msg)
        elif severity == "HIGH":
            logging.error(log_msg)
        elif severity == "MEDIUM":
            logging.warning(log_msg)
        else:
            logging.info(log_msg)
        
        # Keep only last 1000 alerts
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]
    
    def process_packet(self, packet):
        """Process individual packet"""
        self.packet_count += 1
        
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Update traffic statistics
        self.traffic_stats[src_ip]['packet_count'] += 1
        self.traffic_stats[src_ip]['bytes_sent'] += len(packet)
        
        # Check for suspicious TCP flags
        suspicious_flag = self.detect_suspicious_flags(packet)
        if suspicious_flag:
            self.traffic_stats[src_ip]['suspicious_flags'] += 1
            self.generate_alert(
                suspicious_flag,
                "HIGH",
                f"Source: {src_ip}, Destination: {dst_ip}"
            )
        
        # Detect port scanning
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            
            if packet.haslayer(TCP):
                self.traffic_stats[src_ip]['tcp_count'] += 1
            elif packet.haslayer(UDP):
                self.traffic_stats[src_ip]['udp_count'] += 1
            
            if self.detect_port_scan(src_ip, dst_port):
                self.generate_alert(
                    "Port Scan Attack",
                    "CRITICAL",
                    f"Source IP: {src_ip} scanning multiple ports"
                )
        
        # Detect DDoS
        if self.detect_ddos(src_ip):
            self.generate_alert(
                "Possible DDoS Attack",
                "CRITICAL",
                f"Source IP: {src_ip} sending excessive packets"
            )
        
        if packet.haslayer(ICMP):
            self.traffic_stats[src_ip]['icmp_count'] += 1
        
        # ML-based anomaly detection (if model is trained)
        if self.is_trained:
            features = self.extract_features(packet)
            feature_vector = np.array([[
                features['packet_size'],
                features['has_tcp'],
                features['has_udp'],
                features['has_icmp'],
                features['tcp_flags'],
                features['src_port'],
                features['dst_port'],
                features['protocol']
            ]])
            
            scaled_features = self.scaler.transform(feature_vector)
            prediction = self.model.predict(scaled_features)
            
            if prediction[0] == -1:  # Anomaly detected
                self.generate_alert(
                    "ML Anomaly Detection",
                    "MEDIUM",
                    f"Anomalous traffic pattern from {src_ip}"
                )
    
    def train_model(self, training_packets=1000):
        """Train ML model on initial traffic"""
        logging.info(f"Training model on {training_packets} packets...")
        training_data = []
        
        def collect_training_data(packet):
            if packet.haslayer(IP):
                features = self.extract_features(packet)
                training_data.append([
                    features['packet_size'],
                    features['has_tcp'],
                    features['has_udp'],
                    features['has_icmp'],
                    features['tcp_flags'],
                    features['src_port'],
                    features['dst_port'],
                    features['protocol']
                ])
        
        # Collect training data
        sniff(prn=collect_training_data, count=training_packets, 
              iface=self.interface, store=False)
        
        if len(training_data) > 0:
            X_train = np.array(training_data)
            self.scaler.fit(X_train)
            X_scaled = self.scaler.transform(X_train)
            self.model.fit(X_scaled)
            self.is_trained = True
            logging.info("Model training completed")
        else:
            logging.warning("No training data collected")
    
    def start_monitoring(self):
        """Start packet capture and monitoring"""
        self.running = True
        logging.info("Starting IDS monitoring...")
        
        if not self.is_trained:
            logging.info("Training ML model first...")
            self.train_model()
        
        try:
            sniff(prn=self.process_packet, store=False, 
                  iface=self.interface, stop_filter=lambda x: not self.running)
        except KeyboardInterrupt:
            logging.info("Stopping IDS...")
            self.running = False
        except Exception as e:
            logging.error(f"Error during monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
    
    def get_statistics(self):
        """Get current statistics"""
        return {
            'total_packets': self.packet_count,
            'total_alerts': len(self.alerts),
            'recent_alerts': self.alerts[-10:],
            'top_sources': dict(sorted(
                self.traffic_stats.items(),
                key=lambda x: x[1]['packet_count'],
                reverse=True
            )[:10])
        }
    
    def save_alerts(self, filename='alerts.json'):
        """Save alerts to file"""
        with open(filename, 'w') as f:
            json.dump(self.alerts, f, indent=2)
        logging.info(f"Alerts saved to {filename}")


def main():
    print("""
    ╔═══════════════════════════════════════════╗
    ║   Intrusion Detection System (IDS)       ║
    ║   Network Security Monitoring Tool       ║
    ╚═══════════════════════════════════════════╝
    """)
    
    # Check for admin privileges
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Warning: Run as Administrator for full functionality")
        except:
            pass
    else:  # Linux/Mac
        if os.geteuid() != 0:
            print("Warning: Run with sudo for full functionality")
    
    # Get network interface
    interface = input("\nEnter network interface (or press Enter for default): ").strip()
    if not interface:
        interface = None
    
    # Initialize IDS
    ids = IntrusionDetectionSystem(interface=interface)
    
    # Start monitoring in separate thread
    monitor_thread = threading.Thread(target=ids.start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    print("\nIDS is now monitoring network traffic...")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            time.sleep(10)
            stats = ids.get_statistics()
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Statistics:")
            print(f"  Total Packets: {stats['total_packets']}")
            print(f"  Total Alerts: {stats['total_alerts']}")
            
            if stats['recent_alerts']:
                print("\n  Recent Alerts:")
                for alert in stats['recent_alerts'][-3:]:
                    print(f"    [{alert['severity']}] {alert['type']}")
    
    except KeyboardInterrupt:
        print("\n\nStopping IDS...")
        ids.stop_monitoring()
        ids.save_alerts()
        print("\nFinal Statistics:")
        stats = ids.get_statistics()
        print(f"  Total Packets Analyzed: {stats['total_packets']}")
        print(f"  Total Alerts Generated: {stats['total_alerts']}")
        print("\nAlerts saved to alerts.json")
        print("Logs saved to ids_logs.log")


if __name__ == "__main__":
    main()
