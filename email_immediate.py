import time
from datetime import datetime
from email_notifier import EmailNotifier

def test_immediate_alerts():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║        Test IDS Immediate Email Alerts                        ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    print("📧 Initializing email notifier...")
    notifier = EmailNotifier()
    
    if not notifier.enabled:
        print("\n❌ Email notifications are DISABLED in email_config.py")
        print("   Please set 'enable_email': True")
        return
    
    print(f"✅ Email notifications ENABLED")
    print(f"   SMTP Server: {notifier.config['smtp_server']}:{notifier.config['smtp_port']}")
    print(f"   From: {notifier.config['sender_email']}")
    print(f"   To: {', '.join(notifier.config.get('recipient_emails', []))}")
    print(f"   Batch Mode: {'ON' if notifier.batch_alerts else 'OFF (IMMEDIATE)'}")
    print(f"   Alert Threshold: {notifier.config.get('alert_threshold', 'MEDIUM')}")
    
    if notifier.batch_alerts:
        print("\n⚠️  WARNING: Batch mode is ENABLED!")
        print("   Emails will be sent in batches, not immediately.")
        print("   To send emails immediately after detection:")
        print("   Edit email_config.py and set 'batch_alerts': False")
        
        response = input("\n   Continue with batch mode? (y/n): ").strip().lower()
        if response != 'y':
            print("   Test cancelled.")
            return
    else:
        print("\n✅ Immediate alert mode is ACTIVE")
        print("   Emails will be sent right after detection!")
    
    print("\n" + "="*70)
    print("SENDING TEST ALERTS")
    print("="*70)
    
    test_alerts = [
        {
            'type': 'Port Scan Attack',
            'severity': 'CRITICAL',
            'details': 'Source IP: 192.168.1.100 scanning ports 1-1000 on 192.168.1.50'
        },
        {
            'type': 'Possible DDoS Attack',
            'severity': 'CRITICAL',
            'details': 'Source IP: 10.0.0.55 sending 500 packets/second'
        },
        {
            'type': 'XMAS Scan Detected',
            'severity': 'HIGH',
            'details': 'Source: 172.16.0.10, Destination: 172.16.0.100'
        },
        {
            'type': 'ML Anomaly Detection',
            'severity': 'MEDIUM',
            'details': 'Unusual traffic pattern detected from 192.168.10.20'
        }
    ]
    
    print(f"\n🚀 Sending {len(test_alerts)} test alerts...")
    
    for i, alert in enumerate(test_alerts, 1):
        print(f"\n[{i}/{len(test_alerts)}] Sending: {alert['type']} ({alert['severity']})")
        
        notifier.send_alert(
            alert_type=alert['type'],
            severity=alert['severity'],
            details=alert['details'],
            total_packets=1000 + (i * 100),
            total_alerts=i
        )
        
        if notifier.batch_alerts:
            print(f"    ⏳ Alert added to batch queue")
        else:
            print(f"    ✅ Email sent immediately!")
            time.sleep(2)  
    
    print("\n" + "="*70)
    print("TEST COMPLETED")
    print("="*70)
    
    if notifier.batch_alerts:
        print(f"\n📬 {len(notifier.pending_alerts)} alerts in batch queue")
        print(f"   Batch will be sent in {notifier.batch_interval} seconds")
        print("\n   Or force send now by running:")
        print("   >>> from email_notifier import EmailNotifier")
        print("   >>> notifier = EmailNotifier()")
        print("   >>> notifier._send_batch_alerts()")
    else:
        print(f"\n✅ All {len(test_alerts)} emails should be sent!")
        print(f"   Emails sent this session: {notifier.email_count}")
    
    print("\n📬 CHECK YOUR EMAIL INBOX!")
    print("   (Also check spam/junk folder)")
    print(f"\n   Recipients: {', '.join(notifier.config.get('recipient_emails', []))}")
    
    print("\n💡 TIP: If you didn't receive emails:")
    print("   1. Check spam/junk folder")
    print("   2. Verify email_config.py settings")
    print("   3. Make sure 'enable_email': True")
    print("   4. For Gmail, use App Password (not regular password)")
    print("   5. Check ids_logs.log for errors")


if __name__ == "__main__":
    try:
        test_immediate_alerts()
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during test: {e}")
        print("\nPlease check:")
        print("  1. email_config.py exists and is configured")
        print("  2. email_notifier.py exists")
        print("  3. All email settings are correct")
