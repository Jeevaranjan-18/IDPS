import os
import sys
import json
import logging
from datetime import datetime
from collections import defaultdict
import threading
import time

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError as e:
    print(f"Error: Missing required package - {e}")
    print("\nPlease install required packages:")
    print("pip install scapy numpy pandas scikit-learn")
    sys.exit(1)


try:
    from email_notifier import EmailNotifier
    EMAIL_AVAILABLE = True
except ImportError:
    EMAIL_AVAILABLE = False
    print("Warning: Email notification module not found. Email alerts disabled.")


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ids_logs.log'),
        logging.StreamHandler()
    ]
)


class EnhancedNetworkIDS:
    def __init__(self, interface=None, enable_email=True):
        self.interface = interface
        self.packet_count = 0
        self.alerts = []
        self.traffic_stats = defaultdict(lambda: {
            'packet_count': 0,
            'bytes_sent': 0,
            'tcp_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'suspicious_flags': 0,
            'ssh_attempts': 0,
            'ftp_attempts': 0,
            'http_requests': 0
        })
        

        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        

        self.port_scan_threshold = 20
        self.port_scan_window = {}
        

        self.ddos_threshold = 100
        self.ddos_window = {}
        

        self.ssh_attempts = defaultdict(list)
        self.ssh_threshold = 5
        

        self.ftp_sessions = defaultdict(list)
        self.suspicious_file_transfers = []
        

        self.http_requests = defaultdict(list)
        

        self.service_ports = {
            22: 'SSH',
            21: 'FTP',
            20: 'FTP-Data',
            80: 'HTTP',
            443: 'HTTPS',
            23: 'Telnet',
            3389: 'RDP',
            445: 'SMB',
            139: 'NetBIOS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB',
            6379: 'Redis'
        }
        
        self.running = False
        

        self.email_notifier = None
        if EMAIL_AVAILABLE and enable_email:
            try:
                self.email_notifier = EmailNotifier()
                if self.email_notifier.enabled:
                    logging.info("✉️  Email notifications enabled")
            except Exception as e:
                logging.warning(f"Failed to initialize email notifier: {e}")
    
    def extract_features(self, packet):

        features = {
            'packet_size': len(packet),
            'has_tcp': int(packet.haslayer(TCP)),
            'has_udp': int(packet.haslayer(UDP)),
            'has_icmp': int(packet.haslayer(ICMP)),
            'tcp_flags': 0,
            'src_port': 0,
            'dst_port': 0,
            'protocol': 0,
            'payload_size': 0
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
        
        if packet.haslayer(Raw):
            features['payload_size'] = len(packet[Raw].load)
            
        return features
    
    def detect_ssh_attack(self, src_ip, packet):

        if not packet.haslayer(TCP):
            return None
        
        dst_port = packet[TCP].dport
        

        if dst_port == 22:
            current_time = time.time()
            

            self.ssh_attempts[src_ip].append(current_time)
            self.traffic_stats[src_ip]['ssh_attempts'] += 1
            

            self.ssh_attempts[src_ip] = [
                t for t in self.ssh_attempts[src_ip]
                if current_time - t < 60
            ]
            

            if len(self.ssh_attempts[src_ip]) > self.ssh_threshold:
                return "SSH Brute Force Attack"
            

            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)

                if b'SSH-' in payload:
                    return "SSH Connection Attempt"
        
        return None
    
    def detect_ftp_activity(self, src_ip, packet):

        if not packet.haslayer(TCP):
            return None
        
        dst_port = packet[TCP].dport
        

        if dst_port in [20, 21]:
            current_time = time.time()
            self.ftp_sessions[src_ip].append(current_time)
            self.traffic_stats[src_ip]['ftp_attempts'] += 1
            
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                

                ftp_commands = [b'USER', b'PASS', b'RETR', b'STOR', b'LIST', b'PWD']
                for cmd in ftp_commands:
                    if cmd in payload:
                        if cmd in [b'RETR', b'STOR']:
                            return f"FTP File Transfer Detected ({cmd.decode()})"
                        elif cmd == b'PASS':
                            return "FTP Authentication Attempt"
        
        return None
    
    def detect_http_activity(self, packet):

        if not packet.haslayer(TCP):
            return None
        
        dst_port = packet[TCP].dport
        
        if dst_port in [80, 443]:
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                

                http_methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD']
                for method in http_methods:
                    if payload.startswith(method):

                        suspicious_patterns = [
                            b'../../../',
                            b'<script>',
                            b'SELECT * FROM',
                            b'UNION SELECT',
                            b'/etc/passwd',
                            b'cmd.exe',
                            b'/bin/bash'
                        ]
                        
                        for pattern in suspicious_patterns:
                            if pattern in payload:
                                return f"Suspicious HTTP Request (Possible Attack)"
                        

                        if b'Content-Type: multipart' in payload:
                            return "HTTP File Upload Detected"
        
        return None
    
    def detect_port_scan(self, src_ip, dst_port):

        current_time = time.time()
        
        if src_ip not in self.port_scan_window:
            self.port_scan_window[src_ip] = []
        
        self.port_scan_window[src_ip].append((dst_port, current_time))
        

        self.port_scan_window[src_ip] = [
            (port, ts) for port, ts in self.port_scan_window[src_ip]
            if current_time - ts < 10
        ]
        
        unique_ports = len(set(port for port, _ in self.port_scan_window[src_ip]))
        if unique_ports > self.port_scan_threshold:
            return True
        return False
    
    def detect_ddos(self, src_ip):

        current_time = time.time()
        
        if src_ip not in self.ddos_window:
            self.ddos_window[src_ip] = []
        
        self.ddos_window[src_ip].append(current_time)
        
        self.ddos_window[src_ip] = [
            ts for ts in self.ddos_window[src_ip]
            if current_time - ts < 1
        ]
        
        if len(self.ddos_window[src_ip]) > self.ddos_threshold:
            return True
        return False
    
    def detect_suspicious_flags(self, packet):

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if flags == 0:
                return "NULL Scan Detected"
            if flags & 0x29 == 0x29:
                return "XMAS Scan Detected"
            if flags & 0x03 == 0x03:
                return "SYN-FIN Attack Detected"
        return None
    
    def get_service_name(self, port):

        return self.service_ports.get(port, f"Port {port}")
    
    def generate_alert(self, alert_type, severity, details):

        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'details': details
        }
        self.alerts.append(alert)
        

        log_msg = f"[{severity}] {alert_type}: {details}"
        if severity == "CRITICAL":
            logging.critical(log_msg)
        elif severity == "HIGH":
            logging.error(log_msg)
        elif severity == "MEDIUM":
            logging.warning(log_msg)
        else:
            logging.info(log_msg)
        

        if self.email_notifier and self.email_notifier.enabled:
            self.email_notifier.send_alert(
                alert_type=alert_type,
                severity=severity,
                details=details,
                total_packets=self.packet_count,
                total_alerts=len(self.alerts)
            )
        

        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]
    
    def process_packet(self, packet):

        self.packet_count += 1
        
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        

        self.traffic_stats[src_ip]['packet_count'] += 1
        self.traffic_stats[src_ip]['bytes_sent'] += len(packet)
        

        ssh_attack = self.detect_ssh_attack(src_ip, packet)
        if ssh_attack:
            severity = "CRITICAL" if "Brute Force" in ssh_attack else "HIGH"
            self.generate_alert(
                ssh_attack,
                severity,
                f"Source: {src_ip} → Destination: {dst_ip}"
            )
        

        ftp_activity = self.detect_ftp_activity(src_ip, packet)
        if ftp_activity:
            severity = "MEDIUM" if "Transfer" in ftp_activity else "LOW"
            self.generate_alert(
                ftp_activity,
                severity,
                f"Source: {src_ip} → Destination: {dst_ip}"
            )
        

        http_activity = self.detect_http_activity(packet)
        if http_activity:
            severity = "HIGH" if "Attack" in http_activity else "LOW"
            self.generate_alert(
                http_activity,
                severity,
                f"Source: {src_ip} → Destination: {dst_ip}"
            )
        

        suspicious_flag = self.detect_suspicious_flags(packet)
        if suspicious_flag:
            self.traffic_stats[src_ip]['suspicious_flags'] += 1
            self.generate_alert(
                suspicious_flag,
                "HIGH",
                f"Source: {src_ip} → Destination: {dst_ip}"
            )
        

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            service = self.get_service_name(dst_port)
            
            if packet.haslayer(TCP):
                self.traffic_stats[src_ip]['tcp_count'] += 1
            elif packet.haslayer(UDP):
                self.traffic_stats[src_ip]['udp_count'] += 1
            
            if self.detect_port_scan(src_ip, dst_port):
                self.generate_alert(
                    "Port Scan Attack",
                    "CRITICAL",
                    f"Source: {src_ip} scanning multiple ports on {dst_ip} (Including {service})"
                )
        

        if self.detect_ddos(src_ip):
            self.generate_alert(
                "Possible DDoS Attack",
                "CRITICAL",
                f"Source: {src_ip} flooding {dst_ip} ({len(self.ddos_window[src_ip])} packets/second)"
            )
        
        if packet.haslayer(ICMP):
            self.traffic_stats[src_ip]['icmp_count'] += 1
        

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
                features['protocol'],
                features['payload_size']
            ]])
            
            scaled_features = self.scaler.transform(feature_vector)
            prediction = self.model.predict(scaled_features)
            
            if prediction[0] == -1:
                self.generate_alert(
                    "Anomaly Detection",
                    "MEDIUM",
                    f"Anomalous traffic: {src_ip} → {dst_ip}"
                )
    
    def train_model(self, training_packets=1000):

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
                    features['protocol'],
                    features['payload_size']
                ])
        
        sniff(prn=collect_training_data, count=training_packets, 
              iface=self.interface, store=False)
        
        if len(training_data) > 0:
            X_train = np.array(training_data)
            self.scaler.fit(X_train)
            X_scaled = self.scaler.transform(X_train)
            self.model.fit(X_scaled)
            self.is_trained = True
            logging.info("✓ Model training completed")
        else:
            logging.warning("No training data collected")
    
    def start_monitoring(self):

        self.running = True
        logging.info("Starting Enhanced Network IDS...")
        logging.info("Monitoring: SSH, FTP, HTTP, Port Scans, DDoS, Anomalies")
        
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

        self.running = False
    
    def get_statistics(self):

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

        with open(filename, 'w') as f:
            json.dump(self.alerts, f, indent=2)
        logging.info(f"Alerts saved to {filename}")


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                   IDS Ready to Scan on                    ║
    ║     SSH • FTP • HTTP • Port Scans • DDoS • Anomalies      ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    

    if os.name == 'nt':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️  Warning: Run as Administrator for full functionality")
        except:
            pass
    else:
        if os.geteuid() != 0:
            print("⚠️  Warning: Run with sudo for full functionality")
            print("   Example: sudo python3 ids_main.py\n")
    

    if EMAIL_AVAILABLE:
        print("✉️  Email notification module found")
        test_email = input("   Test email configuration? (y/n): ").strip().lower()
        if test_email == 'y':
            from email_notifier import test_email_setup
            test_email_setup()
            print()
    else:
        print("ℹ️  Email notifications not available")
    

    print("\n📡 Network Interfaces:")
    print("   Common: eth0, wlan0, en0, Wi-Fi, Ethernet")
    interface = input("   Enter network interface (or press Enter for default): ").strip()
    if not interface:
        interface = None
    

    ids = EnhancedNetworkIDS(interface=interface, enable_email=True)
    

    monitor_thread = threading.Thread(target=ids.start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    print("\n🛡️  IDS is now monitoring network traffic...")
    print("   Press Ctrl+C to stop\n")
    
    print("🔍 Monitoring for:")
    print("   • SSH brute force attacks")
    print("   • FTP file transfers")
    print("   • Suspicious HTTP requests")
    print("   • Port scanning")
    print("   • DDoS attacks")
    print("   • Network anomalies\n")
    
    if ids.email_notifier and ids.email_notifier.enabled:
        recipients = ', '.join(ids.email_notifier.config.get('recipient_emails', []))
        print(f"📧 Email alerts → {recipients}\n")
    
    try:
        while True:
            time.sleep(10)
            stats = ids.get_statistics()
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Statistics:")
            print(f"  📊 Total Packets: {stats['total_packets']}")
            print(f"  ⚠️  Total Alerts: {stats['total_alerts']}")
            
            if stats['recent_alerts']:
                print("\n  Recent Alerts:")
                for alert in stats['recent_alerts'][-3:]:
                    severity_icon = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }.get(alert['severity'], '⚪')
                    print(f"    {severity_icon} [{alert['severity']}] {alert['type']}")
    
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping IDS...")
        ids.stop_monitoring()
        ids.save_alerts()
        
        print("\n📊 Final Statistics:")
        stats = ids.get_statistics()
        print(f"  Total Packets Analyzed: {stats['total_packets']}")
        print(f"  Total Alerts Generated: {stats['total_alerts']}")
        
        print("\n📈 Attack Statistics:")
        total_ssh = sum(s['ssh_attempts'] for s in ids.traffic_stats.values())
        total_ftp = sum(s['ftp_attempts'] for s in ids.traffic_stats.values())
        total_http = sum(s['http_requests'] for s in ids.traffic_stats.values())
        
        if total_ssh > 0:
            print(f"  🔐 SSH Attempts: {total_ssh}")
        if total_ftp > 0:
            print(f"  📁 FTP Activities: {total_ftp}")
        if total_http > 0:
            print(f"  🌐 HTTP Requests: {total_http}")
        
        print("\n💾 Data saved:")
        print("  • Alerts: alerts.json")
        print("  • Logs: ids_logs.log")
        
        if ids.email_notifier and ids.email_notifier.enabled:
            print(f"  • Emails sent: {ids.email_notifier.email_count}")


if __name__ == "__main__":
    main()
