import os
import sys
import json
from datetime import datetime
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from utils.analysis import analyze_pcap

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///netguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database Models
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    packet_count = db.Column(db.Integer)
    malicious_count = db.Column(db.Integer)
    protocols_json = db.Column(db.Text) 
    src_ips_json = db.Column(db.Text)
    dst_ips_json = db.Column(db.Text)
    alerts = db.relationship('Alert', backref='scan', lazy=True)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    type = db.Column(db.String(50))
    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))
    port = db.Column(db.String(20))
    protocol = db.Column(db.String(20))
    payload = db.Column(db.Text)
    full_hex = db.Column(db.Text)
    full_ascii = db.Column(db.Text)
    details = db.Column(db.Text)
    timestamp = db.Column(db.String(50))
    # SIEM Enhancement Fields
    severity = db.Column(db.String(20), default='MEDIUM')
    risk_score = db.Column(db.Integer, default=50)
    mitre_tactic = db.Column(db.String(20))
    mitre_technique = db.Column(db.String(20))
    threat_category = db.Column(db.String(50))
    packet_details_json = db.Column(db.Text)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return jsonify({"status": "NetGuard API is running", "version": "2.0"})

@app.route('/api/history')
def history():
    scans = Scan.query.order_by(Scan.timestamp.desc()).all()
    return jsonify([{
        'id': s.id,
        'filename': s.filename,
        'timestamp': s.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'packet_count': s.packet_count,
        'malicious_count': s.malicious_count
    } for s in scans])

@app.route('/api/report/<int:scan_id>')
def report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    alerts = [{
        'type': a.type,
        'src_ip': a.src_ip,
        'dst_ip': a.dst_ip,
        'port': a.port,
        'protocol': a.protocol,
        'payload': a.payload,
        'full_hex': a.full_hex,
        'full_ascii': a.full_ascii,
        'details': a.details,
        'timestamp': a.timestamp,
        'severity': a.severity,
        'risk_score': a.risk_score,
        'mitre_tactic': a.mitre_tactic,
        'mitre_technique': a.mitre_technique,
        'threat_category': a.threat_category,
        'packet_details': json.loads(a.packet_details_json) if a.packet_details_json else {}
    } for a in scan.alerts]
    
    return jsonify({
        'id': scan.id,
        'filename': scan.filename,
        'timestamp': scan.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'packet_count': scan.packet_count,
        'malicious_count': scan.malicious_count,
        'protocols': json.loads(scan.protocols_json),
        'src_ips': json.loads(scan.src_ips_json),
        'dst_ips': json.loads(scan.dst_ips_json),
        'malicious_activity': alerts
    })

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            results = analyze_pcap(filepath)
            
            new_scan = Scan(
                filename=filename,
                packet_count=results['packet_count'],
                malicious_count=len(results['malicious_activity']),
                protocols_json=json.dumps(results['protocols']),
                src_ips_json=json.dumps(results['src_ips']),
                dst_ips_json=json.dumps(results['dst_ips'])
            )
            db.session.add(new_scan)
            db.session.commit()

            for alert in results['malicious_activity']:
                new_alert = Alert(
                    scan_id=new_scan.id,
                    type=alert.get('type'),
                    src_ip=alert.get('src_ip'),
                    dst_ip=alert.get('dst_ip'),
                    port=str(alert.get('port', 'N/A')),
                    protocol=str(alert.get('protocol', 'N/A')),
                    payload=alert.get('payload', 'N/A'),
                    full_hex=alert.get('full_hex', 'N/A'),
                    full_ascii=alert.get('full_ascii', 'N/A'),
                    details=alert.get('details'),
                    timestamp=alert.get('timestamp', 'N/A'),
                    severity=alert.get('severity', 'MEDIUM'),
                    risk_score=alert.get('risk_score', 50),
                    mitre_tactic=alert.get('mitre_tactic', 'N/A'),
                    mitre_technique=alert.get('mitre_technique', 'N/A'),
                    threat_category=alert.get('threat_category', 'Unknown'),
                    packet_details_json=json.dumps(alert.get('packet_details', {}))
                )
                db.session.add(new_alert)
            db.session.commit()

            results['scan_id'] = new_scan.id
            return jsonify(results)

        except Exception as e:
            return jsonify({'error': str(e)}), 500
            
    return jsonify({'error': 'Invalid file type'}), 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=8080)
