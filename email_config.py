EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': 'jeevaranjan180506@gmail.com',
    'sender_password': 'ogkztcymjjuukein',
    'recipient_emails': [
        'jeevs1808.m@gmail.com'
    ],
    'enable_email': True,
    'alert_threshold': 'MEDIUM',
    'batch_alerts': True,
    'batch_interval': 300,
    'max_emails_per_hour': 10,
}

EMAIL_SUBJECT_TEMPLATE = "[IDS ALERT - {severity}] {alert_type}"

EMAIL_BODY_TEMPLATE = """
╔═══════════════════════════════════════════════════════════════╗
║           INTRUSION DETECTION SYSTEM ALERT                    ║
╚═══════════════════════════════════════════════════════════════╝

⚠️  SECURITY ALERT DETECTED

Alert Type: {alert_type}
Severity: {severity}
Timestamp: {timestamp}

Details:
{details}

─────────────────────────────────────────────────────────────────

System Information:
- Total Packets Analyzed: {total_packets}
- Total Alerts Generated: {total_alerts}
- Active Monitoring: Yes

─────────────────────────────────────────────────────────────────

Recommended Actions:
{recommendations}

─────────────────────────────────────────────────────────────────

This is an automated alert from your Intrusion Detection System.
Please review and take appropriate action.

Do not reply to this email.
"""

BATCH_EMAIL_TEMPLATE = """
╔═══════════════════════════════════════════════════════════════╗
║           INTRUSION DETECTION SYSTEM - BATCH ALERTS           ║
╚═══════════════════════════════════════════════════════════════╝

Summary: {alert_count} security alerts detected in the last {time_period}

═══════════════════════════════════════════════════════

{alerts_summary}

═══════════════════════════════════════════════════════

System Statistics:
- Total Packets Analyzed: {total_packets}
- Total Alerts: {total_alerts}
- Critical Alerts: {critical_count}
- High Priority Alerts: {high_count}

═══════════════════════════════════════

Please review the dashboard for detailed information.
Dashboard: http://localhost:5000

This is an automated batch alert from your IDS.
"""

ALERT_RECOMMENDATIONS = {
    'Port Scan Attack': """
    1. Block the source IP address in your firewall
    2. Review firewall rules to prevent unauthorized port access
    3. Enable connection rate limiting
    4. Monitor for follow-up exploitation attempts
    """,
    
    'Possible DDoS Attack': """
    1. Implement rate limiting on affected services
    2. Consider enabling DDoS mitigation services
    3. Block or throttle the attacking IP addresses
    4. Scale up resources if legitimate traffic is affected
    5. Contact your ISP for upstream filtering
    """,
    
    'NULL Scan Detected': """
    1. Block the source IP immediately
    2. This is a reconnaissance attempt - expect follow-up attacks
    3. Review and strengthen firewall rules
    4. Enable SYN cookies if not already enabled
    """,
    
    'XMAS Scan Detected': """
    1. Block the source IP address
    2. Attacker is attempting to identify open ports
    3. Ensure all unnecessary services are disabled
    4. Update firewall rules to drop malformed packets
    """,
    
    'SYN-FIN Attack Detected': """
    1. Block source IP - this is malicious traffic
    2. Enable TCP state tracking in firewall
    3. Review connection logs for other anomalies
    4. Consider implementing IPS rules
    """,
    
    'ML Anomaly Detection': """
    1. Investigate the source IP and traffic pattern
    2. Review recent network changes that might cause false positives
    3. If confirmed malicious, block the source
    4. Update ML model with new legitimate traffic patterns
    """
}

SMTP_SERVERS = {
    'gmail': {
        'server': 'smtp.gmail.com',
        'port': 587,
        'note': 'Use App Password, not regular password. Enable 2FA first.'
    },
    'outlook': {
        'server': 'smtp-mail.outlook.com',
        'port': 587,
        'note': 'Use your regular Outlook password'
    },
    'yahoo': {
        'server': 'smtp.mail.yahoo.com',
        'port': 587,
        'note': 'Generate app password from Yahoo account security'
    },
    'office365': {
        'server': 'smtp.office365.com',
        'port': 587,
        'note': 'Use your Office 365 credentials'
    },
    'custom': {
        'server': 'your-smtp-server.com',
        'port': 587,
        'note': 'Contact your email provider for SMTP settings'
    }
}
