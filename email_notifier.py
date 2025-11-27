import smtplib
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from collections import deque
import logging

try:
    from email_config import (
        EMAIL_CONFIG, 
        EMAIL_SUBJECT_TEMPLATE, 
        EMAIL_BODY_TEMPLATE,
        BATCH_EMAIL_TEMPLATE,
        ALERT_RECOMMENDATIONS
    )
except ImportError:
    print("Warning: email_config.py not found. Email notifications disabled.")
    EMAIL_CONFIG = {'enable_email': False}


class EmailNotifier:
    """Handles email notifications for IDS alerts"""
    
    def __init__(self, config=None):
        self.config = config or EMAIL_CONFIG
        self.enabled = self.config.get('enable_email', False)
        
        if not self.enabled:
            logging.info("Email notifications are disabled")
            return
        
        self.email_count = 0
        self.email_reset_time = datetime.now() + timedelta(hours=1)
        self.max_emails_per_hour = self.config.get('max_emails_per_hour', 10)
        
        self.batch_alerts = self.config.get('batch_alerts', True)
        self.batch_interval = self.config.get('batch_interval', 300)
        self.pending_alerts = deque()
        self.last_batch_send = datetime.now()
        
        severity_levels = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        threshold = self.config.get('alert_threshold', 'MEDIUM')
        self.min_severity = severity_levels.get(threshold, 1)
        
        if self.batch_alerts:
            self.batch_thread = threading.Thread(target=self._batch_processor, daemon=True)
            self.batch_thread.start()
        
        logging.info(f"Email notifications enabled. Threshold: {threshold}")
    
    def _reset_rate_limit(self):
        """Reset email rate limiting counter"""
        if datetime.now() >= self.email_reset_time:
            self.email_count = 0
            self.email_reset_time = datetime.now() + timedelta(hours=1)
    
    def _check_rate_limit(self):
        """Check if rate limit exceeded"""
        self._reset_rate_limit()
        return self.email_count < self.max_emails_per_hour
    
    def _should_send_alert(self, severity):
        """Determine if alert severity meets threshold"""
        severity_levels = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        alert_level = severity_levels.get(severity, 0)
        return alert_level >= self.min_severity
    
    def _get_recommendations(self, alert_type):
        """Get recommended actions for alert type"""
        return ALERT_RECOMMENDATIONS.get(
            alert_type, 
            "1. Investigate the alert details\n2. Review system logs\n3. Take appropriate security measures"
        )
    
    def _send_email(self, subject, body, recipients=None):
        """Send email using SMTP"""
        try:
            if recipients is None:
                recipients = self.config.get('recipient_emails', [])
            
            if not recipients:
                logging.error("No recipient emails configured")
                return False
            
            msg = MIMEMultipart('alternative')
            msg['From'] = self.config['sender_email']
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                server.starttls()
                server.login(self.config['sender_email'], self.config['sender_password'])
                server.send_message(msg)
            
            self.email_count += 1
            logging.info(f"Email sent successfully to {len(recipients)} recipient(s)")
            return True
            
        except smtplib.SMTPAuthenticationError:
            logging.error("SMTP Authentication failed. Check your email credentials.")
            logging.error("For Gmail, use an App Password, not your regular password.")
            return False
        except smtplib.SMTPException as e:
            logging.error(f"SMTP error occurred: {e}")
            return False
        except Exception as e:
            logging.error(f"Failed to send email: {e}")
            return False
    
    def send_alert(self, alert_type, severity, details, total_packets=0, total_alerts=0):
        """Send individual alert email"""
        if not self.enabled:
            return
        
        if not self._should_send_alert(severity):
            return
        
        if self.batch_alerts:
            self.pending_alerts.append({
                'alert_type': alert_type,
                'severity': severity,
                'details': details,
                'timestamp': datetime.now().isoformat(),
                'total_packets': total_packets,
                'total_alerts': total_alerts
            })
            return
        
        if not self._check_rate_limit():
            logging.warning("Email rate limit reached. Alert not sent.")
            return
        
        subject = EMAIL_SUBJECT_TEMPLATE.format(
            severity=severity,
            alert_type=alert_type
        )
        
        body = EMAIL_BODY_TEMPLATE.format(
            alert_type=alert_type,
            severity=severity,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            details=details,
            total_packets=total_packets,
            total_alerts=total_alerts,
            recommendations=self._get_recommendations(alert_type)
        )
        
        email_thread = threading.Thread(
            target=self._send_email,
            args=(subject, body),
            daemon=True
        )
        email_thread.start()
    
    def _batch_processor(self):
        """Process and send batch alerts periodically"""
        while True:
            time.sleep(30)
            
            time_since_last = (datetime.now() - self.last_batch_send).total_seconds()
            
            if time_since_last >= self.batch_interval and len(self.pending_alerts) > 0:
                self._send_batch_alerts()
    
    def _send_batch_alerts(self):
        """Send accumulated alerts in a single email"""
        if not self.pending_alerts:
            return
        
        if not self._check_rate_limit():
            logging.warning("Email rate limit reached. Batch alerts delayed.")
            return
        
        alerts_summary = ""
        critical_count = 0
        high_count = 0
        
        for i, alert in enumerate(self.pending_alerts, 1):
            if alert['severity'] == 'CRITICAL':
                critical_count += 1
            elif alert['severity'] == 'HIGH':
                high_count += 1
            
            alerts_summary += f"""
Alert #{i}:
├─ Type: {alert['alert_type']}
├─ Severity: {alert['severity']}
├─ Time: {alert['timestamp']}
└─ Details: {alert['details']}

"""
        
        last_alert = list(self.pending_alerts)[-1]
        
        first_time = datetime.fromisoformat(list(self.pending_alerts)[0]['timestamp'])
        last_time = datetime.fromisoformat(last_alert['timestamp'])
        time_period = str(last_time - first_time).split('.')[0]
        
        subject = f"[IDS BATCH ALERT] {len(self.pending_alerts)} Security Alerts"
        
        body = BATCH_EMAIL_TEMPLATE.format(
            alert_count=len(self.pending_alerts),
            time_period=time_period,
            alerts_summary=alerts_summary,
            total_packets=last_alert['total_packets'],
            total_alerts=last_alert['total_alerts'],
            critical_count=critical_count,
            high_count=high_count
        )
        
        success = self._send_email(subject, body)
        
        if success:
            self.pending_alerts.clear()
            self.last_batch_send = datetime.now()
            logging.info(f"Batch alert sent successfully")
    
    def send_test_email(self):
        """Send a test email to verify configuration"""
        if not self.enabled:
            print("❌ Email notifications are disabled in config")
            return False
        
        subject = "[IDS TEST] Email Configuration Test"
        body = """
╔═══════════════════════════════════════════════════════════════╗
║              Email from IDS scanning is running               ║
╚═══════════════════════════════════════════════════════════════╝

This is a  email from  Intrusion Detection System is running .

To verify,  If you received this email, your email configuration is working correctly!

Configuration Details:
- SMTP Server: {smtp_server}:{smtp_port}
- Sender: {sender_email}
- Test Time: {timestamp}

Your IDS is now ready to send security alerts.

═══════════════════════════════════════════════════════════════
""".format(
            smtp_server=self.config['smtp_server'],
            smtp_port=self.config['smtp_port'],
            sender_email=self.config['sender_email'],
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        print("\n📧 Sending test email...")
        success = self._send_email(subject, body)
        
        if success:
            print("✅ Test email sent successfully!")
            print(f"   Check inbox for: {', '.join(self.config.get('recipient_emails', []))}")
            return True
        else:
            print("❌ Failed to send test email. Check your configuration.")
            return False


def test_email_setup():
    """Interactive test for email setup"""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║           IDS Email Notification Setup Test                   ║
╚═══════════════════════════════════════════════════════════════╝
""")
    
    notifier = EmailNotifier()
    
    if not notifier.enabled:
        print("\n⚠️  Email notifications are currently disabled.")
        print("   Edit email_config.py and set 'enable_email': True")
        return
    
    print(f"\n📧 Email Configuration:")
    print(f"   SMTP Server: {notifier.config['smtp_server']}:{notifier.config['smtp_port']}")
    print(f"   Sender: {notifier.config['sender_email']}")
    print(f"   Recipients: {', '.join(notifier.config.get('recipient_emails', []))}")
    print(f"   Batch Alerts: {'Enabled' if notifier.batch_alerts else 'Disabled'}")
    print(f"   Min Severity: {notifier.config.get('alert_threshold', 'MEDIUM')}")
    
    response = input("\nSend test email? (y/n): ").strip().lower()
    
    if response == 'y':
        notifier.send_test_email()
    else:
        print("Test cancelled.")

if __name__ == "__main__":
    test_email_setup()
