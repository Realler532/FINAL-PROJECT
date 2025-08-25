#!/usr/bin/env python3
"""
Advanced Real-Time Threat Detection Backend
Multi-layered security system with ML-powered threat detection
"""

import asyncio
import json
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any
import logging
import uuid
import hashlib
import re
import ipaddress

# Web framework and async support
from flask import Flask, request, jsonify, Response
from flask_socketio import SocketIO, emit
import requests
from concurrent.futures import ThreadPoolExecutor

# ML and data analysis
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

# Network and security
import socket
import struct

@dataclass
class ThreatEvent:
    """Threat event data structure"""
    id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    threat_type: str
    severity: int  # 1-10 scale
    confidence: float  # 0.0-1.0
    description: str
    indicators: List[str]
    raw_data: Dict[str, Any]
    blocked: bool = False
    false_positive: bool = False

class ThreatIntelligence:
    """Threat intelligence and reputation system"""
    
    def __init__(self):
        self.malicious_ips = set()
        self.suspicious_domains = set()
        self.known_malware_hashes = set()
        self.threat_feeds = []
        self.reputation_cache = {}
        self.last_update = None
        
        # Initialize with some basic threat data
        self.load_default_threats()
    
    def load_default_threats(self):
        """Load default threat intelligence"""
        # Known malicious IP ranges (examples)
        self.malicious_networks = [
            ipaddress.ip_network('10.0.0.0/8'),  # Private range for demo
            ipaddress.ip_network('192.168.0.0/16'),  # Private range for demo
        ]
        
        # Known malicious domains
        self.suspicious_domains.update([
            'malware.com', 'phishing.net', 'botnet.org',
            'c2server.evil', 'trojan.download'
        ])
        
        # Sample malware hashes
        self.known_malware_hashes.update([
            'a1b2c3d4e5f6', 'deadbeefcafe', 'malware123456'
        ])
    
    def check_ip_reputation(self, ip: str) -> Tuple[bool, str, float]:
        """Check IP reputation"""
        try:
            ip_addr = ipaddress.ip_address(ip)
            
            # Check against malicious networks
            for network in self.malicious_networks:
                if ip_addr in network:
                    return True, f"IP in known malicious network {network}", 0.9
            
            # Check direct IP matches
            if ip in self.malicious_ips:
                return True, "IP in threat intelligence feed", 0.95
                
            # Simulate external reputation check
            reputation_score = self.get_reputation_score(ip)
            if reputation_score < 0.3:
                return True, f"Poor reputation score: {reputation_score}", reputation_score
                
        except ValueError:
            pass
            
        return False, "Clean", 1.0
    
    def get_reputation_score(self, ip: str) -> float:
        """Simulate reputation scoring"""
        # In real implementation, query external APIs like VirusTotal, AbuseIPDB
        if ip in self.reputation_cache:
            return self.reputation_cache[ip]
        
        # Simulate scoring based on IP characteristics
        octets = ip.split('.')
        if len(octets) == 4:
            try:
                score = (int(octets[0]) + int(octets[3])) / 510.0
                self.reputation_cache[ip] = score
                return score
            except ValueError:
                pass
        
        return 0.5  # Neutral score

class BehavioralAnalyzer:
    """ML-powered behavioral analysis engine"""
    
    def __init__(self):
        self.connection_patterns = defaultdict(list)
        self.traffic_features = deque(maxlen=1000)
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.model_trained = False
        self.baseline_established = False
        
    def extract_features(self, event_data: Dict) -> List[float]:
        """Extract features for ML analysis"""
        features = [
            event_data.get('packet_size', 0),
            event_data.get('connection_duration', 0),
            event_data.get('bytes_transferred', 0),
            event_data.get('packets_per_second', 0),
            event_data.get('unique_ports', 0),
            event_data.get('protocol_diversity', 0),
            event_data.get('time_between_connections', 0),
            hash(event_data.get('source_ip', '')) % 1000,  # IP hash feature
            len(event_data.get('payload', b'')),
        ]
        return features
    
    def analyze_behavior(self, source_ip: str, event_data: Dict) -> Tuple[bool, float, str]:
        """Analyze behavioral patterns"""
        features = self.extract_features(event_data)
        self.traffic_features.append(features)
        
        # Store connection patterns
        self.connection_patterns[source_ip].append({
            'timestamp': datetime.now(),
            'features': features
        })
        
        # Train model if we have enough data
        if len(self.traffic_features) >= 100 and not self.model_trained:
            self.train_anomaly_detection()
        
        # Perform anomaly detection
        if self.model_trained:
            scaled_features = self.scaler.transform([features])
            anomaly_score = self.isolation_forest.decision_function(scaled_features)[0]
            is_anomaly = self.isolation_forest.predict(scaled_features)[0] == -1
            
            if is_anomaly:
                return True, abs(anomaly_score), f"Behavioral anomaly detected (score: {anomaly_score:.3f})"
        
        # Rule-based behavioral analysis
        return self.rule_based_behavior_analysis(source_ip, event_data)
    
    def train_anomaly_detection(self):
        """Train the anomaly detection model"""
        try:
            features_array = np.array(list(self.traffic_features))
            scaled_features = self.scaler.fit_transform(features_array)
            self.isolation_forest.fit(scaled_features)
            self.model_trained = True
            logging.info("Anomaly detection model trained successfully")
        except Exception as e:
            logging.error(f"Failed to train anomaly detection model: {e}")
    
    def rule_based_behavior_analysis(self, source_ip: str, event_data: Dict) -> Tuple[bool, float, str]:
        """Rule-based behavioral analysis"""
        # Rapid connection analysis
        recent_connections = [
            conn for conn in self.connection_patterns[source_ip]
            if (datetime.now() - conn['timestamp']).seconds < 60
        ]
        
        if len(recent_connections) > 50:
            return True, 0.8, f"Rapid connection pattern: {len(recent_connections)} connections in 1 minute"
        
        # Port scanning detection
        unique_ports = len(set(conn['features'][4] for conn in recent_connections))
        if unique_ports > 20:
            return True, 0.9, f"Port scanning behavior: {unique_ports} unique ports"
        
        # Data volume analysis
        total_bytes = sum(conn['features'][2] for conn in recent_connections)
        if total_bytes > 10_000_000:  # 10MB in 1 minute
            return True, 0.7, f"High data volume: {total_bytes:,} bytes in 1 minute"
        
        return False, 0.1, "Normal behavior"

class SignatureEngine:
    """Signature-based threat detection"""
    
    def __init__(self):
        self.malware_signatures = self.load_malware_signatures()
        self.attack_patterns = self.load_attack_patterns()
        self.regex_patterns = self.compile_regex_patterns()
    
    def load_malware_signatures(self) -> Dict[str, Dict]:
        """Load malware signatures"""
        return {
            'trojan_generic': {
                'patterns': [b'trojan', b'backdoor', b'keylogger'],
                'severity': 9,
                'description': 'Generic trojan signature'
            },
            'ransomware_pattern': {
                'patterns': [b'encrypt', b'ransom', b'bitcoin'],
                'severity': 10,
                'description': 'Ransomware activity detected'
            },
            'botnet_c2': {
                'patterns': [b'bot', b'command', b'control'],
                'severity': 8,
                'description': 'Botnet command and control'
            }
        }
    
    def load_attack_patterns(self) -> Dict[str, Dict]:
        """Load attack patterns"""
        return {
            'sql_injection': {
                'patterns': [b'union select', b'drop table', b"'; exec", b'xp_cmdshell'],
                'severity': 7,
                'description': 'SQL injection attempt'
            },
            'xss_attack': {
                'patterns': [b'<script>', b'javascript:', b'onerror=', b'onload='],
                'severity': 6,
                'description': 'Cross-site scripting attempt'
            },
            'command_injection': {
                'patterns': [b';cat ', b'|nc ', b'&& ', b'|| ', b'`whoami`'],
                'severity': 8,
                'description': 'Command injection attempt'
            },
            'directory_traversal': {
                'patterns': [b'../', b'..\\', b'etc/passwd', b'boot.ini'],
                'severity': 7,
                'description': 'Directory traversal attempt'
            }
        }
    
    def compile_regex_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for faster matching"""
        patterns = {}
        
        # Suspicious URLs
        patterns['malicious_url'] = re.compile(
            rb'(malware|phishing|trojan|exploit|payload)\.(?:com|net|org)',
            re.IGNORECASE
        )
        
        # Suspicious file extensions
        patterns['malicious_file'] = re.compile(
            rb'\.(?:exe|scr|bat|cmd|pif|com|vbs|jar|app)$',
            re.IGNORECASE
        )
        
        # Base64 encoded payloads
        patterns['base64_payload'] = re.compile(
            rb'[A-Za-z0-9+/]{100,}={0,2}',
        )
        
        return patterns
    
    def analyze_payload(self, payload: bytes) -> List[Tuple[str, int, str]]:
        """Analyze payload for signatures"""
        threats = []
        payload_lower = payload.lower()
        
        # Check malware signatures
        for sig_name, sig_data in self.malware_signatures.items():
            for pattern in sig_data['patterns']:
                if pattern in payload_lower:
                    threats.append((
                        'malware_signature',
                        sig_data['severity'],
                        f"{sig_data['description']}: {pattern.decode('utf-8', errors='ignore')}"
                    ))
        
        # Check attack patterns
        for attack_name, attack_data in self.attack_patterns.items():
            for pattern in attack_data['patterns']:
                if pattern in payload_lower:
                    threats.append((
                        attack_name,
                        attack_data['severity'],
                        f"{attack_data['description']}: {pattern.decode('utf-8', errors='ignore')}"
                    ))
        
        # Check regex patterns
        for pattern_name, regex in self.regex_patterns.items():
            if regex.search(payload):
                threats.append((
                    pattern_name,
                    6,
                    f"Suspicious {pattern_name.replace('_', ' ')} detected"
                ))
        
        return threats

class RealTimeThreatDetector:
    """Main threat detection engine"""
    
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.signature_engine = SignatureEngine()
        
        # Threat storage and statistics
        self.active_threats = {}
        self.threat_history = deque(maxlen=10000)
        self.threat_stats = defaultdict(int)
        self.blocked_ips = set()
        
        # Real-time processing
        self.event_queue = asyncio.Queue()
        self.processing_active = False
        
        # Configuration
        self.auto_block_threshold = 8  # Auto-block threats with severity >= 8
        self.correlation_window = 300  # 5 minutes
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    async def process_network_event(self, event_data: Dict) -> Optional[ThreatEvent]:
        """Process network event for threats"""
        threats_detected = []
        max_severity = 0
        all_indicators = []
        
        source_ip = event_data.get('source_ip', '')
        dest_ip = event_data.get('destination_ip', '')
        payload = event_data.get('payload', b'')
        
        # 1. IP Reputation Check
        is_malicious, reputation_msg, confidence = self.threat_intel.check_ip_reputation(source_ip)
        if is_malicious:
            threats_detected.append(('ip_reputation', 7, reputation_msg))
            all_indicators.append(f"Malicious IP: {source_ip}")
        
        # 2. Signature-based Detection
        signature_threats = self.signature_engine.analyze_payload(payload)
        threats_detected.extend(signature_threats)
        
        # 3. Behavioral Analysis
        is_anomaly, behavior_confidence, behavior_msg = self.behavioral_analyzer.analyze_behavior(
            source_ip, event_data
        )
        if is_anomaly:
            severity = min(9, int(behavior_confidence * 10))
            threats_detected.append(('behavioral_anomaly', severity, behavior_msg))
            all_indicators.append(f"Behavioral anomaly: {behavior_confidence:.2f}")
        
        # 4. Protocol-specific analysis
        protocol_threats = self.analyze_protocol_specific(event_data)
        threats_detected.extend(protocol_threats)
        
        # Create threat event if any threats detected
        if threats_detected:
            max_severity = max(threat[1] for threat in threats_detected)
            threat_descriptions = [threat[2] for threat in threats_detected]
            
            threat_event = ThreatEvent(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                source_ip=source_ip,
                destination_ip=dest_ip,
                threat_type=threats_detected[0][0],
                severity=max_severity,
                confidence=max(confidence, behavior_confidence if is_anomaly else 0.5),
                description="; ".join(threat_descriptions),
                indicators=all_indicators,
                raw_data=event_data
            )
            
            # Auto-block high severity threats
            if max_severity >= self.auto_block_threshold:
                threat_event.blocked = True
                self.blocked_ips.add(source_ip)
                self.logger.critical(f"AUTO-BLOCKED: {source_ip} - Severity {max_severity}")
            
            # Store and update statistics
            self.active_threats[threat_event.id] = threat_event
            self.threat_history.append(threat_event)
            self.threat_stats['total'] += 1
            self.threat_stats[threat_event.threat_type] += 1
            self.threat_stats[f'severity_{max_severity}'] += 1
            
            self.logger.warning(
                f"THREAT DETECTED: {source_ip} -> {dest_ip} "
                f"[{threat_event.threat_type}] Severity: {max_severity}"
            )
            
            return threat_event
        
        return None
    
    def analyze_protocol_specific(self, event_data: Dict) -> List[Tuple[str, int, str]]:
        """Protocol-specific threat analysis"""
        threats = []
        protocol = event_data.get('protocol', '').upper()
        
        if protocol == 'TCP':
            # TCP-specific analysis
            flags = event_data.get('tcp_flags', 0)
            src_port = event_data.get('source_port', 0)
            dst_port = event_data.get('destination_port', 0)
            
            # Suspicious TCP flags
            if flags == 0:  # NULL scan
                threats.append(('tcp_null_scan', 6, 'TCP NULL scan detected'))
            elif flags == 0x29:  # XMAS scan
                threats.append(('tcp_xmas_scan', 6, 'TCP XMAS scan detected'))
            
            # Suspicious ports
            if dst_port in [1337, 31337, 12345, 54321]:
                threats.append(('suspicious_port', 7, f'Connection to suspicious port {dst_port}'))
        
        elif protocol == 'UDP':
            dst_port = event_data.get('destination_port', 0)
            packet_size = event_data.get('packet_size', 0)
            
            # DNS tunneling detection
            if dst_port == 53 and packet_size > 512:
                threats.append(('dns_tunneling', 8, f'Possible DNS tunneling: {packet_size} bytes'))
        
        elif protocol == 'ICMP':
            icmp_type = event_data.get('icmp_type', 0)
            packet_size = event_data.get('packet_size', 0)
            
            # Large ICMP packets (possible data exfiltration)
            if packet_size > 1000:
                threats.append(('icmp_exfiltration', 7, f'Large ICMP packet: {packet_size} bytes'))
        
        return threats
    
    def correlate_threats(self) -> List[Dict]:
        """Correlate related threats"""
        correlations = []
        now = datetime.now()
        window_start = now - timedelta(seconds=self.correlation_window)
        
        # Get recent threats
        recent_threats = [
            threat for threat in self.threat_history
            if threat.timestamp >= window_start
        ]
        
        # Group by source IP
        ip_threats = defaultdict(list)
        for threat in recent_threats:
            ip_threats[threat.source_ip].append(threat)
        
        # Look for patterns
        for source_ip, threats in ip_threats.items():
            if len(threats) >= 3:  # Multiple threats from same IP
                correlations.append({
                    'type': 'coordinated_attack',
                    'source_ip': source_ip,
                    'threat_count': len(threats),
                    'severity': max(t.severity for t in threats),
                    'timespan': (threats[-1].timestamp - threats[0].timestamp).seconds,
                    'description': f'Coordinated attack from {source_ip}: {len(threats)} threats'
                })
        
        return correlations
    
    def get_threat_statistics(self) -> Dict:
        """Get comprehensive threat statistics"""
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        
        recent_threats = [
            threat for threat in self.threat_history
            if threat.timestamp >= hour_ago
        ]
        
        daily_threats = [
            threat for threat in self.threat_history
            if threat.timestamp >= day_ago
        ]
        
        return {
            'total_threats': len(self.threat_history),
            'active_threats': len(self.active_threats),
            'blocked_ips': len(self.blocked_ips),
            'threats_last_hour': len(recent_threats),
            'threats_last_24h': len(daily_threats),
            'threat_types': dict(self.threat_stats),
            'top_threat_ips': self.get_top_threat_ips(10),
            'severity_distribution': self.get_severity_distribution(),
            'correlations': self.correlate_threats()
        }
    
    def get_top_threat_ips(self, limit: int = 10) -> List[Dict]:
        """Get top threatening IP addresses"""
        ip_counts = defaultdict(int)
        ip_severity = defaultdict(int)
        
        for threat in self.threat_history:
            ip_counts[threat.source_ip] += 1
            ip_severity[threat.source_ip] = max(
                ip_severity[threat.source_ip],
                threat.severity
            )
        
        top_ips = sorted(
            ip_counts.items(),
            key=lambda x: (x[1], ip_severity[x[0]]),
            reverse=True
        )[:limit]
        
        return [
            {
                'ip': ip,
                'threat_count': count,
                'max_severity': ip_severity[ip],
                'blocked': ip in self.blocked_ips
            }
            for ip, count in top_ips
        ]
    
    def get_severity_distribution(self) -> Dict[str, int]:
        """Get threat severity distribution"""
        distribution = defaultdict(int)
        for threat in self.threat_history:
            severity_range = f"{(threat.severity // 2) * 2}-{(threat.severity // 2) * 2 + 1}"
            distribution[severity_range] += 1
        return dict(distribution)

# Flask Web API
app = Flask(__name__)
app.config['SECRET_KEY'] = 'threat_detection_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global threat detector instance
threat_detector = RealTimeThreatDetector()

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get recent threats"""
    limit = request.args.get('limit', 100, type=int)
    recent_threats = list(threat_detector.threat_history)[-limit:]
    
    return jsonify([
        {
            'id': threat.id,
            'timestamp': threat.timestamp.isoformat(),
            'source_ip': threat.source_ip,
            'destination_ip': threat.destination_ip,
            'threat_type': threat.threat_type,
            'severity': threat.severity,
            'confidence': threat.confidence,
            'description': threat.description,
            'indicators': threat.indicators,
            'blocked': threat.blocked
        }
        for threat in recent_threats
    ])

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get threat statistics"""
    return jsonify(threat_detector.get_threat_statistics())

@app.route('/api/block/<ip>', methods=['POST'])
def block_ip(ip):
    """Manually block an IP"""
    threat_detector.blocked_ips.add(ip)
    threat_detector.logger.info(f"Manually blocked IP: {ip}")
    return jsonify({'status': 'success', 'message': f'IP {ip} blocked'})

@app.route('/api/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    """Unblock an IP"""
    threat_detector.blocked_ips.discard(ip)
    threat_detector.logger.info(f"Unblocked IP: {ip}")
    return jsonify({'status': 'success', 'message': f'IP {ip} unblocked'})

@app.route('/api/submit_event', methods=['POST'])
def submit_event():
    """Submit network event for analysis"""
    event_data = request.json
    
    async def process_event():
        threat_event = await threat_detector.process_network_event(event_data)
        if threat_event:
            # Emit real-time threat notification
            socketio.emit('threat_detected', {
                'id': threat_event.id,
                'timestamp': threat_event.timestamp.isoformat(),
                'source_ip': threat_event.source_ip,
                'threat_type': threat_event.threat_type,
                'severity': threat_event.severity,
                'description': threat_event.description,
                'blocked': threat_event.blocked
            })
            
            return asdict(threat_event)
        return None
    
    # Run async processing
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        result = loop.run_until_complete(process_event())
        if result:
            return jsonify({'status': 'threat_detected', 'threat': result})
        else:
            return jsonify({'status': 'clean'})
    finally:
        loop.close()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_threats': len(threat_detector.active_threats),
        'blocked_ips': len(threat_detector.blocked_ips)
    })

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    emit('connected', {'status': 'Connected to threat detection system'})

@socketio.on('subscribe_threats')
def handle_subscribe():
    """Subscribe to real-time threat updates"""
    emit('subscribed', {'message': 'Subscribed to real-time threat updates'})

def simulate_network_traffic():
    """Simulate network traffic for testing"""
    import random
    
    sample_events = [
        {
            'source_ip': '192.168.1.100',
            'destination_ip': '10.0.0.5',
            'protocol': 'TCP',
            'source_port': 12345,
            'destination_port': 80,
            'packet_size': 1024,
            'payload': b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
        },
        {
            'source_ip': '172.16.0.50',
            'destination_ip': '8.8.8.8',
            'protocol': 'UDP',
            'source_port': 53,
            'destination_port': 53,
            'packet_size': 1500,
            'payload': b'suspicious dns tunneling data' * 20
        },
        {
            'source_ip': '10.0.0.99',
            'destination_ip': '192.168.1.1',
            'protocol': 'TCP',
            'source_port': 1337,
            'destination_port': 4444,
            'packet_size': 2048,
            'payload': b'trojan backdoor malware payload'
        }
    ]
    
    while True:
        event = random.choice(sample_events).copy()
        event['source_ip'] = f"192.168.1.{random.randint(1, 254)}"
        
        async def process_sim_event():
            await threat_detector.process_network_event(event)
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(process_sim_event())
        finally:
            loop.close()
        
        time.sleep(random.uniform(0.1, 2.0))

if __name__ == '__main__':
    print("🛡️  Advanced Real-Time Threat Detection Backend")
    print("=" * 50)
    print("🔍 Multi-layered security analysis")
    print("🤖 ML-powered behavioral detection")
    print("📡 Real-time threat intelligence")
    print("🌐 REST API and WebSocket support")
    print()
    print("API Endpoints:")
    print("  GET  /api/threats - Get recent threats")
    print("  GET  /api/statistics - Get threat statistics")
    print("  POST /api/submit_event - Submit network event")
    print("  POST /api/block/<ip> - Block IP address")
    print("  GET  /api/health - Health check")
    print()
    
    # Start simulation thread for testing
    simulation_thread = threading.Thread(target=simulate_network_traffic, daemon=True)
    simulation_thread.start()
    
    # Start the web server
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
