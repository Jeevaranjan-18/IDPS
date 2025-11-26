"""
IDS Web Dashboard
Flask-based web interface for monitoring intrusion detection alerts
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
CORS(app)

# HTML template
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
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #333;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            background: white;
            padding: 20px 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        h1 {
            color: #1e3c72;
            font-size: 2em;
            margin-bottom: 5px;
        }
        
        .subtitle {
            color: #666;
            font-size: 0.9em;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #1e3c72;
        }
        
        .alerts-container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .section-title {
            font-size: 1.5em;
            color: #1e3c72;
            margin-bottom: 20px;
            border-bottom: 3px solid #1e3c72;
            padding-bottom: 10px;
        }
        
        .alert-item {
            padding: 15px;
            border-left: 4px solid #ccc;
            margin-bottom: 15px;
            background: #f9f9f9;
            border-radius: 5px;
            transition: all 0.3s ease;
        }
        
        .alert-item:hover {
            background: #f0f0f0;
            transform: translateX(5px);
        }
        
        .alert-item.critical {
            border-left-color: #dc3545;
            background: #fff5f5;
        }
        
        .alert-item.high {
            border-left-color: #fd7e14;
            background: #fff8f0;
        }
        
        .alert-item.medium {
            border-left-color: #ffc107;
            background: #fffbf0;
        }
        
        .alert-item.low {
            border-left-color: #28a745;
            background: #f0fff4;
        }
        
        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .alert-type {
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .alert-severity {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-critical {
            background: #dc3545;
            color: white;
        }
        
        .severity-high {
            background: #fd7e14;
            color: white;
        }
        
        .severity-medium {
            background: #ffc107;
            color: #333;
        }
        
        .severity-low {
            background: #28a745;
            color: white;
        }
        
        .alert-time {
            color: #666;
            font-size: 0.85em;
            margin-bottom: 5px;
        }
        
        .alert-details {
            color: #444;
            font-size: 0.95em;
        }
        
        .no-alerts {
            text-align: center;
            padding: 40px;
            color: #999;
            font-style: italic;
        }
        
        .refresh-btn {
            background: #1e3c72;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
            margin-bottom: 20px;
            transition: background 0.3s ease;
        }
        
        .refresh-btn:hover {
            background: #2a5298;
        }
        
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #28a745;
            animation: pulse 2s infinite;
            margin-right: 8px;
        }
        
        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.5;
            }
        }
        
        .chart-container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Intrusion Detection System Dashboard</h1>
            <p class="subtitle">
                <span class="status-indicator"></span>
                Real-time Network Security Monitoring
            </p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Packets</h3>
                <div class="stat-value" id="total-packets">0</div>
            </div>
            <div class="stat-card">
                <h3>Total Alerts</h3>
                <div class="stat-value" id="total-alerts">0</div>
            </div>
            <div class="stat-card">
                <h3>Critical Alerts</h3>
                <div class="stat-value" id="critical-alerts" style="color: #dc3545;">0</div>
            </div>
            <div class="stat-card">
                <h3>Active Threats</h3>
                <div class="stat-value" id="active-threats" style="color: #fd7e14;">0</div>
            </div>
        </div>
        
        <div class="alerts-container">
            <button class="refresh-btn" onclick="loadData()">🔄 Refresh Data</button>
            <h2 class="section-title">Recent Security Alerts</h2>
            <div id="alerts-list">
                <div class="no-alerts">No alerts to display. System is monitoring...</div>
            </div>
        </div>
    </div>
    
    <script>
        function loadData() {
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => {
                    // Update statistics
                    document.getElementById('total-packets').textContent = data.total_packets || 0;
                    document.getElementById('total-alerts').textContent = data.alerts.length;
                    
                    // Count critical alerts
                    const criticalCount = data.alerts.filter(a => a.severity === 'CRITICAL').length;
                    document.getElementById('critical-alerts').textContent = criticalCount;
                    
                    // Active threats (alerts in last 5 minutes)
                    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
                    const activeThreats = data.alerts.filter(a => {
                        return new Date(a.timestamp) > fiveMinutesAgo;
                    }).length;
                    document.getElementById('active-threats').textContent = activeThreats;
                    
                    // Display alerts
                    const alertsList = document.getElementById('alerts-list');
                    if (data.alerts.length === 0) {
                        alertsList.innerHTML = '<div class="no-alerts">No alerts to display. System is monitoring...</div>';
                    } else {
                        alertsList.innerHTML = data.alerts.slice(-20).reverse().map(alert => {
                            const time = new Date(alert.timestamp).toLocaleString();
                            const severityClass = alert.severity.toLowerCase();
                            return `
                                <div class="alert-item ${severityClass}">
                                    <div class="alert-header">
                                        <span class="alert-type">${alert.type}</span>
                                        <span class="alert-severity severity-${severityClass}">${alert.severity}</span>
                                    </div>
                                    <div class="alert-time">⏰ ${time}</div>
                                    <div class="alert-details">${alert.details}</div>
                                </div>
                            `;
                        }).join('');
                    }
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
        # Try to load alerts from file
        if os.path.exists('alerts.json'):
            with open('alerts.json', 'r') as f:
                alerts = json.load(f)
        else:
            alerts = []
        
        # Try to load logs for packet count
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
    """Get detailed statistics"""
    try:
        if os.path.exists('alerts.json'):
            with open('alerts.json', 'r') as f:
                alerts = json.load(f)
        else:
            alerts = []
        
        # Analyze alerts
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        for alert in alerts:
            severity_counts[alert['severity']] += 1
            type_counts[alert['type']] += 1
        
        return jsonify({
            'severity_distribution': dict(severity_counts),
            'type_distribution': dict(type_counts),
            'total_alerts': len(alerts)
        })
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════╗
    ║       IDS Web Dashboard Server           ║
    ╚═══════════════════════════════════════════╝
    
    Starting dashboard server...
    Open your browser and navigate to:
    
    🌐 http://localhost:5000
    
    Press Ctrl+C to stop the server
    """)
    app.run(debug=True, host='0.0.0.0', port=5000)
