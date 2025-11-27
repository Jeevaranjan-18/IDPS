"""
Enhanced IDS Web Dashboard with Categorized Alerts
Flask-based web interface with severity-based organization
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
CORS(app)

# Enhanced HTML template with categorized alerts
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDS Dashboard</title>
   <style>
            * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(to right, #E2E8F0 0%, #CBD5E1 100%);
    color: #0F172A;
    min-height: 100vh;
    padding: 20px;
}

.container {
    max-width: 1600px;
    margin: 0 auto;
}

/* ---------------- HEADER ---------------- */

header {
    background: white;
    padding: 25px 35px;
    border-radius: 12px;
    box-shadow: 0 4px 10px rgba(15, 23, 42, 0.15);
    margin-bottom: 30px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border: 1px solid #E2E8F0;
}

.header-left h1 {
    color: #1E3A8A;
    font-size: 2.2em;
    margin-bottom: 5px;
}

.subtitle {
    color: #475569;
    font-size: 0.95em;
}

.status-indicator {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: #10B981;
    margin-right: 8px;
}

/* ---------------- HEADER RIGHT ---------------- */

.header-right {
    text-align: right;
}

.last-update {
    color: #475569;
    font-size: 0.9em;
    margin-bottom: 10px;
}

.refresh-btn {
    background: #1D4ED8;
    color: white;
    border: none;
    padding: 12px 25px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 1em;
    transition: all 0.3s ease;
    display: inline-flex;
    align-items: center;
    gap: 8px;
}

.refresh-btn:hover {
    background: #2563EB;
    transform: translateY(-2px);
}

/* ---------------- STAT CARDS ---------------- */

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.stat-card {
    background: white;
    padding: 25px;
    border-radius: 12px;
    border-left: 5px solid #1D4ED8;
    box-shadow: 0 4px 8px rgba(15, 23, 42, 0.1);
    transition: transform 0.3s ease;
}

.stat-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 6px 14px rgba(15, 23, 42, 0.15);
}

/* Severity Colors */
.stat-card.critical { border-left-color: #EF4444; }
.stat-card.high { border-left-color: #F97316; }
.stat-card.medium { border-left-color: #EAB308; }
.stat-card.low { border-left-color: #10B981; }

.stat-card h3 {
    color: #475569;
    font-size: 0.85em;
    margin-bottom: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.stat-value {
    font-size: 2.8em;
    font-weight: bold;
    color: #1D4ED8;
}

.stat-card.critical .stat-value { color: #EF4444; }
.stat-card.high .stat-value { color: #F97316; }
.stat-card.medium .stat-value { color: #EAB308; }
.stat-card.low .stat-value { color: #10B981; }

/* ----------------- SUMMARY SECTION ----------------- */

.summary-section {
    background: white;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 4px 8px rgba(15,23,42,0.1);
    margin-bottom: 30px;
    border: 1px solid #E2E8F0;
}

.summary-title {
    font-size: 1.5em;
    color: #1D4ED8;
    margin-bottom: 20px;
    border-bottom: 3px solid #1D4ED8;
    padding-bottom: 10px;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
}

.summary-item {
    padding: 15px;
    background: #F8FAFC;
    border-radius: 8px;
    border-left: 4px solid #1D4ED8;
}

.summary-item h4 {
    color: #475569;
    margin-bottom: 8px;
}

.summary-item .value {
    font-size: 1.8em;
    font-weight: bold;
    color: #1D4ED8;
}

/* ---------------- ALERTS SECTION ---------------- */

.alerts-section {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
    gap: 25px;
    margin-bottom: 30px;
}

.alert-category {
    background: white;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 4px 8px rgba(15,23,42,0.1);
    border: 1px solid #E2E8F0;
}

.category-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 3px solid;
}

.alert-category.critical .category-header { border-bottom-color: #EF4444; }
.alert-category.high .category-header { border-bottom-color: #F97316; }
.alert-category.medium .category-header { border-bottom-color: #EAB308; }
.alert-category.low .category-header { border-bottom-color: #10B981; }

.category-title {
    font-size: 1.4em;
    font-weight: bold;
    display: flex;
    align-items: center;
    gap: 10px;
}

.category-count {
    background: #F1F5F9;
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 0.9em;
    font-weight: bold;
    color: #1E293B;
}

/* Alert Items */

.alert-item {
    padding: 16px;
    margin-bottom: 12px;
    background: #F8FAFC;
    border-radius: 8px;
    border-left: 4px solid #1D4ED8;
    transition: all 0.3s ease;
}

.alert-category.critical .alert-item { border-left-color: #EF4444; background: #FEF2F2; }
.alert-category.high .alert-item { border-left-color: #F97316; background: #FFF7ED; }
.alert-category.medium .alert-item { border-left-color: #EAB308; background: #FEFCE8; }
.alert-category.low .alert-item { border-left-color: #10B981; background: #ECFDF5; }

.alert-item:hover {
    transform: translateX(5px);
    background: #F1F5F9;
}

.alert-type {
    font-weight: bold;
    font-size: 1em;
    margin-bottom: 6px;
    color: #334155;
}

.alert-time {
    color: #64748B;
    font-size: 0.8em;
    margin-bottom: 6px;
}

.alert-details {
    color: #475569;
    font-size: 0.9em;
}

/* No alerts */
.no-alerts {
    text-align: center;
    padding: 30px;
    color: #94A3B8;
    font-style: italic;
}

/* Chart Placeholder */
.chart-placeholder {
    height: 200px;
    background: #F1F5F9;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #94A3B8;
    margin-top: 15px;
}

   </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-left">
                <h1>🛡️ IDS Scanning Platform </h1>
                <p class="subtitle">
                    <span class="status-indicator"></span>
                    Real-time Network Security Monitoring
                </p>
            </div>
            <div class="header-right">
                <div class="last-update">Last updated: <span id="last-update">--:--:--</span></div>
                <button class="refresh-btn" onclick="loadData()">
                     Refresh Data
                </button>
            </div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Packets</h3>
                <div class="stat-value" id="total-packets">0</div>
            </div>
            <div class="stat-card critical">
                <h3>🔴 Critical Alerts</h3>
                <div class="stat-value" id="critical-count">0</div>
            </div>
            <div class="stat-card high">
                <h3>🟠 High Priority</h3>
                <div class="stat-value" id="high-count">0</div>
            </div>
            <div class="stat-card medium">
                <h3>🟡 Medium Priority</h3>
                <div class="stat-value" id="medium-count">0</div>
            </div>
            <div class="stat-card low">
                <h3>🟢 Low Priority</h3>
                <div class="stat-value" id="low-count">0</div>
            </div>
            <div class="stat-card">
                <h3>Total Alerts</h3>
                <div class="stat-value" id="total-alerts">0</div>
            </div>
        </div>
        
        <div class="summary-section">
            <h2 class="summary-title">📊 Attack Summary by Category</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h4>🔐 SSH Attacks</h4>
                    <div class="value" id="ssh-count">0</div>
                </div>
                <div class="summary-item">
                    <h4>📁 FTP Activities</h4>
                    <div class="value" id="ftp-count">0</div>
                </div>
                <div class="summary-item">
                    <h4>🌐 HTTP Attacks</h4>
                    <div class="value" id="http-count">0</div>
                </div>
                <div class="summary-item">
                    <h4>🔍 Port Scans</h4>
                    <div class="value" id="portscan-count">0</div>
                </div>
                <div class="summary-item">
                    <h4>💥 DDoS Attempts</h4>
                    <div class="value" id="ddos-count">0</div>
                </div>
                <div class="summary-item">
                    <h4>⚠️ Anomalies</h4>
                    <div class="value" id="anomaly-count">0</div>
                </div>
            </div>
        </div>
        
        <div class="alerts-section">
            <div class="alert-category critical">
                <div class="category-header">
                    <div class="category-title">
                        <span class="icon">🔴</span>
                        Critical Alerts
                    </div>
                    <div class="category-count" id="critical-badge">0</div>
                </div>
                <div id="critical-alerts">
                    <div class="no-alerts">No critical alerts</div>
                </div>
            </div>
            
            <div class="alert-category high">
                <div class="category-header">
                    <div class="category-title">
                        <span class="icon">🟠</span>
                        High Priority
                    </div>
                    <div class="category-count" id="high-badge">0</div>
                </div>
                <div id="high-alerts">
                    <div class="no-alerts">No high priority alerts</div>
                </div>
            </div>
            
            <div class="alert-category medium">
                <div class="category-header">
                    <div class="category-title">
                        <span class="icon">🟡</span>
                        Medium Priority
                    </div>
                    <div class="category-count" id="medium-badge">0</div>
                </div>
                <div id="medium-alerts">
                    <div class="no-alerts">No medium priority alerts</div>
                </div>
            </div>
            
            <div class="alert-category low">
                <div class="category-header">
                    <div class="category-title">
                        <span class="icon">🟢</span>
                        Low Priority
                    </div>
                    <div class="category-count" id="low-badge">0</div>
                </div>
                <div id="low-alerts">
                    <div class="no-alerts">No low priority alerts</div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function categorizeAlerts(alerts) {
            const categories = {
                CRITICAL: [],
                HIGH: [],
                MEDIUM: [],
                LOW: []
            };
            
            alerts.forEach(alert => {
                const severity = alert.severity || 'LOW';
                if (categories[severity]) {
                    categories[severity].push(alert);
                }
            });
            
            return categories;
        }
        
        function countByType(alerts) {
            const counts = {
                ssh: 0,
                ftp: 0,
                http: 0,
                portscan: 0,
                ddos: 0,
                anomaly: 0
            };
            
            alerts.forEach(alert => {
                const type = alert.type.toLowerCase();
                if (type.includes('ssh')) counts.ssh++;
                else if (type.includes('ftp')) counts.ftp++;
                else if (type.includes('http')) counts.http++;
                else if (type.includes('port scan')) counts.portscan++;
                else if (type.includes('ddos')) counts.ddos++;
                else if (type.includes('anomaly')) counts.anomaly++;
            });
            
            return counts;
        }
        
        function renderAlerts(containerId, alerts) {
            const container = document.getElementById(containerId);
            
            if (alerts.length === 0) {
                container.innerHTML = '<div class="no-alerts">No alerts in this category</div>';
                return;
            }
            
            container.innerHTML = alerts.slice(-10).reverse().map(alert => {
                const time = new Date(alert.timestamp).toLocaleString();
                return `
                    <div class="alert-item">
                        <div class="alert-type">${alert.type}</div>
                        <div class="alert-time"> ${time}</div>
                        <div class="alert-details">${alert.details}</div>
                    </div>
                `;
            }).join('');
        }
        
        function loadData() {
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => {
                    // Update last update time
                    const now = new Date();
                    document.getElementById('last-update').textContent = now.toLocaleTimeString();
                    
                    // Update total stats
                    document.getElementById('total-packets').textContent = data.total_packets || 0;
                    document.getElementById('total-alerts').textContent = data.alerts.length;
                    
                    // Categorize alerts
                    const categorized = categorizeAlerts(data.alerts);
                    
                    // Update severity counts
                    document.getElementById('critical-count').textContent = categorized.CRITICAL.length;
                    document.getElementById('high-count').textContent = categorized.HIGH.length;
                    document.getElementById('medium-count').textContent = categorized.MEDIUM.length;
                    document.getElementById('low-count').textContent = categorized.LOW.length;
                    
                    // Update badges
                    document.getElementById('critical-badge').textContent = categorized.CRITICAL.length;
                    document.getElementById('high-badge').textContent = categorized.HIGH.length;
                    document.getElementById('medium-badge').textContent = categorized.MEDIUM.length;
                    document.getElementById('low-badge').textContent = categorized.LOW.length;
                    
                    // Count by attack type
                    const typeCounts = countByType(data.alerts);
                    document.getElementById('ssh-count').textContent = typeCounts.ssh;
                    document.getElementById('ftp-count').textContent = typeCounts.ftp;
                    document.getElementById('http-count').textContent = typeCounts.http;
                    document.getElementById('portscan-count').textContent = typeCounts.portscan;
                    document.getElementById('ddos-count').textContent = typeCounts.ddos;
                    document.getElementById('anomaly-count').textContent = typeCounts.anomaly;
                    
                    // Render alerts by category
                    renderAlerts('critical-alerts', categorized.CRITICAL);
                    renderAlerts('high-alerts', categorized.HIGH);
                    renderAlerts('medium-alerts', categorized.MEDIUM);
                    renderAlerts('low-alerts', categorized.LOW);
                })
                .catch(error => {
                    console.error('Error loading data:', error);
                });
        }
        
        // Load data on page load
        loadData();
        
        // Auto-refresh every 5 seconds
        setInterval(loadData, 5000);
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return HTML_TEMPLATE

@app.route('/api/alerts')
def get_alerts():
    """API endpoint to get alerts"""
    try:
        if os.path.exists('alerts.json'):
            with open('alerts.json', 'r') as f:
                alerts = json.load(f)
        else:
            alerts = []
        
        total_packets = 0
        if os.path.exists('ids_logs.log'):
            with open('ids_logs.log', 'r') as f:
                for line in f:
                    if 'Total Packets' in line:
                        try:
                            total_packets = int(line.split(':')[-1].strip())
                        except:
                            pass
        
        return jsonify({
            'alerts': alerts,
            'total_packets': total_packets
        })
    except Exception as e:
        return jsonify({
            'alerts': [],
            'total_packets': 0,
            'error': str(e)
        })

@app.route('/api/statistics')
def get_statistics():
    """Get detailed statistics categorized by severity"""
    try:
        if os.path.exists('alerts.json'):
            with open('alerts.json', 'r') as f:
                alerts = json.load(f)
        else:
            alerts = []
        
        # Categorize by severity
        severity_counts = defaultdict(int)
        for alert in alerts:
            severity_counts[alert.get('severity', 'LOW')] += 1
        
        # Categorize by type
        type_counts = defaultdict(int)
        for alert in alerts:
            alert_type = alert.get('type', 'Unknown')
            type_counts[alert_type] += 1
        
        return jsonify({
            'severity_distribution': dict(severity_counts),
            'type_distribution': dict(type_counts),
            'total_alerts': len(alerts)
        })
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     Enhanced IDS Dashboard - Categorized by Severity     ║
    ╚═══════════════════════════════════════════════════════════╝
    
    Starting dashboard server...
    
    Features:
    • Alerts organized by severity (Critical, High, Medium, Low)
    • Real-time attack statistics by category
    • SSH, FTP, HTTP, Port Scan, DDoS tracking
    • Auto-refresh every 5 seconds
    
    Open your browser and navigate to:
    
    🌐 http://localhost:5000
    
    Press Ctrl+C to stop the server
    """)
    app.run(debug=True, host='0.0.0.0', port=5000)
