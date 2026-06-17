# ForensicLogX — Real-Time Linux Log Analyzer & Threat Detection System

**Final Year Project** | BS Digital Forensics & Cyber Security  
**Student:** Gohar Ali | **Roll:** FA-22-BSDFCS-095  
**Institution:** [Your University]  
**Year:** 2024-2025

---

## 📋 Project Overview

**ForensicLogX** is a sophisticated real-time Linux log analysis and threat detection system designed for security professionals and organizations. It leverages industry-standard detection frameworks (OWASP CRS and Sigma rules) to identify and categorize web application attacks with high precision and minimal false positives.

### 🎯 Key Features

- **Real-Time Threat Detection**: Streaming log analysis with WebSocket-based live updates
- **Multi-Detection Framework**: 
  - OWASP ModSecurity Core Rule Set (CRS) integration
  - Sigma rule engine for behavior-based detection
  - Custom rule library with 30+ threat signatures
- **Web-Based Dashboard**: Interactive React/Vite frontend with live threat visualization
- **Advanced Analytics**:
  - Attack classification and categorization
  - IP intelligence and geolocation tracking
  - False positive handling and tuning
  - Comprehensive reporting with PDF export
- **Log Integrity**: SHA256-based file hash verification
- **Scalable Architecture**: Flask-SocketIO for real-time broadcasting to multiple clients

---

## 📊 Technical Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LOG SOURCES                              │
│  Apache/Nginx │ ModSecurity Audit │ System Logs            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ (tail -f or replay)
                     ▼
         ┌──────────────────────────┐
         │  agent.py                │
         │  (Producer)              │
         └────────┬─────────────────┘
                  │ WebSocket (real-time)
                  ▼
    ┌─────────────────────────────────────────┐
    │         app.py (Flask + SocketIO)       │
    │  ┌────────────────────────────────────┐ │
    │  │  realtime_engine.py                │ │
    │  │  - Stream Processing              │ │
    │  │  - Alert Aggregation              │ │
    │  └────────────────────────────────────┘ │
    │  ┌────────────────────────────────────┐ │
    │  │  threat_engine.py                  │ │
    │  │  - CRS Detection                   │ │
    │  │  - Sigma Rules                     │ │
    │  │  - False Positive Filtering        │ │
    │  └────────────────────────────────────┘ │
    │  ┌────────────────────────────────────┐ │
    │  │  report_generator.py               │ │
    │  │  - PDF Export                      │ │
    │  │  - Analytics                       │ │
    │  └────────────────────────────────────┘ │
    └─────────────┬──────────────────────────┘
                  │ WebSocket Broadcast
                  ▼
         ┌──────────────────────────┐
         │  soar-lite/              │
         │  React Dashboard         │
         │  (Vite + TailwindCSS)    │
         └──────────────────────────┘
         
         Database: SQLite (CRS rules, alerts)
```

---

## 🚀 Quick Start (3 Steps)

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Start the Server
```bash
python app.py
```
Opens automatically at: **http://127.0.0.1:5000**

### Step 3: Start the Log Agent (new terminal)
```bash
# Option A: Simulate live attack traffic (recommended for demo)
python agent.py --simulate-attacks

# Option B: Replay a sample log file
python agent.py --file dataset/dvwa_test_logs.jsonl --simulate

# Option C: Tail a real Apache log (Linux only)
python agent.py --file /var/log/apache2/access.log

# Option D: Send events via CLI
python cli.py detect --log-path /path/to/log.txt
```

---

## 📁 Project Structure

```
ForensicLogX/
├── app.py                      # Flask main application + SocketIO
├── agent.py                    # Log producer/feeder agent
├── cli.py                      # Command-line interface
├── log_agent.py                # Alternative agent implementation
├── requirements.txt            # Python dependencies
│
├── backend/                    # Core detection & parsing logic
│   ├── threat_engine.py        # Main threat detection (CRS + Sigma)
│   ├── realtime_engine.py      # Stream processing & aggregation
│   ├── crs_parser.py           # CRS rule file parser
│   ├── crs_detector.py         # CRS-based detection
│   ├── sigma_engine.py         # Sigma rule execution
│   ├── attack_categorizer.py   # Attack classification
│   ├── modsec_log_parser.py    # ModSecurity audit log parsing
│   ├── report_generator.py     # PDF report generation
│   ├── detection_rules.py      # Custom threat signatures
│   ├── regex_library.py        # Regex patterns for detection
│   ├── ioc_library.py          # Indicators of Compromise (IOCs)
│   ├── fp_handler.py           # False positive handling
│   ├── ip_blocker.py           # IP-based threat intelligence
│   ├── integrity.py            # File hash verification (SHA256)
│   ├── models.py               # SQLAlchemy ORM models
│   ├── config.py               # Configuration management
│   ├── routes.py               # REST API endpoints
│   ├── crs_routes.py           # CRS-specific endpoints
│   └── socket_events.py        # WebSocket event handlers
│
├── frontend/                   # React-based dashboard
│   ├── templates/              # HTML templates
│   ├── static/                 # CSS, JS, images
│   └── soar-lite/              # Vite + React app
│       ├── src/
│       │   ├── pages/          # Dashboard pages
│       │   ├── components/     # Reusable components
│       │   └── data/           # Mock data
│       └── vite.config.js
│
├── dataset/                    # Rules & sample data
│   ├── rules/                  # OWASP CRS rule files
│   ├── sigma/                  # Sigma detection rules
│   ├── dvwa_test_logs.jsonl    # Sample attack logs
│   └── docs/                   # Rule documentation
│
├── tests/                      # Unit & integration tests
│   ├── test_backend.py
│   ├── test_detections.py
│   └── test_crs_integration.py
│
├── uploads/                    # Uploaded log files & analysis results
├── reports/                    # Generated PDF reports
├── logs/                       # Application logs
└── hashes/                     # File integrity hashes

```

---

## 🔍 Core Components

### 1. **Threat Engine** (`backend/threat_engine.py`)
- Analyzes log entries against 30+ threat signatures
- Returns structured threat objects with:
  - Rule ID and category
  - Severity (low/medium/high/critical)
  - MITRE ATT&CK mapping
  - Confidence scores with false positive adjustment

### 2. **CRS Integration** (`backend/crs_parser.py` + `backend/crs_detector.py`)
- Parses OWASP ModSecurity CRS rule files (~1000+ rules)
- Performs pattern matching on HTTP requests/responses
- Detects: SQLi, XSS, LFI, RFI, RCE, protocol attacks

### 3. **Sigma Engine** (`backend/sigma_engine.py`)
- Loads Sigma YAML rules for behavior-based detection
- Supports log filtering and aggregation
- Detects suspicious user activity, privilege escalation, lateral movement

### 4. **Real-Time Stream Processor** (`backend/realtime_engine.py`)
- Buffers incoming log events (5-second windows)
- Aggregates alerts by IP/attack type
- Broadcasts updates via WebSocket to all connected clients

### 5. **False Positive Handler** (`backend/fp_handler.py`)
- Evaluates alert confidence against known false positive patterns
- Whitelist management for legitimate traffic
- Reduces noise in high-traffic environments

### 6. **Report Generator** (`backend/report_generator.py`)
- Creates detailed PDF reports with:
  - Attack timeline and statistics
  - Top attacking IPs and attack types
  - MITRE mapping heatmaps
  - Remediation recommendations

---

## 📈 Detection Capabilities

| Category | Technique | Rule Count |
|----------|-----------|-----------|
| **SQL Injection** | SQLi patterns, time-based, error-based | 15+ |
| **XSS** | Reflected/Stored/DOM-based | 12+ |
| **LFI/RFI** | Path traversal, remote includes | 8+ |
| **RCE** | Code execution patterns, shell metacharacters | 10+ |
| **Reconnaissance** | Scanner detection, enumeration | 6+ |
| **Protocol Attacks** | Malformed requests, HTTP smuggling | 8+ |

---

## 🖥️ API Endpoints

### Dashboard
- `GET /` — Main dashboard

### Detection & Analysis
- `POST /api/detect` — Analyze a log entry
- `GET /api/alerts` — Retrieve alerts (paginated)
- `GET /api/stats` — System statistics

### Reports
- `GET /api/reports` — List generated reports
- `POST /api/reports/generate` — Create new report
- `GET /api/reports/<id>/pdf` — Download PDF

### CRS Management
- `GET /api/crs/rules` — List all CRS rules
- `GET /api/crs/rules/<id>` — Rule details
- `POST /api/crs/rules/<id>/toggle` — Enable/disable rule

### File Upload & Integrity
- `POST /api/upload` — Upload log file
- `GET /api/integrity/<file_id>` — Verify file hash

---

## 🔐 Security Features

- **File Integrity Verification**: SHA256 hashing for audit trails
- **False Positive Filtering**: Confidence scoring with whitelist rules
- **Rate Limiting**: Protects against log flooding attacks
- **Input Validation**: Sanitization of all API inputs
- **CORS Configuration**: Restricted cross-origin access

---

## 📊 Threat Severity Scoring

| Score | Severity | Action |
|-------|----------|--------|
| 80-100 | 🔴 **CRITICAL** | Immediate block & investigation |
| 50-79 | 🟠 **HIGH** | Alert security team |
| 20-49 | 🟡 **MEDIUM** | Log & monitor |
| 0-19 | 🟢 **LOW** | Informational |

---

## 🧪 Testing

Run unit tests:
```bash
pytest tests/
```

Run integration tests:
```bash
pytest tests/test_crs_integration.py -v
```

---

## 📝 Configuration

Edit `backend/config.py` to adjust:
- Upload folder paths
- Report generation settings
- Database connection strings
- WebSocket configuration

---

## 🚀 Deployment

### Local Development
```bash
python app.py  # Runs on http://localhost:5000
```

### Production (Ubuntu/Linux Server)
See `DEPLOYMENT.md` for complete setup guide including:
- Ubuntu agent setup
- Apache/Nginx integration
- ModSecurity configuration
- Systemd service creation

---

## 📚 Dependencies

### Backend
- **Flask 3.0+**: Web framework
- **Flask-SocketIO 5.3+**: Real-time WebSocket support
- **Pandas 2.0+**: Data analysis
- **SQLAlchemy 2.0+**: ORM
- **ReportLab 4.0+**: PDF generation

### Frontend
- **React 18+**: UI framework
- **Vite**: Build tool
- **TailwindCSS**: Styling
- **Axios**: HTTP client

---

## 🤝 Contributing

This is a Final Year Project. Contributions are welcome for:
- Additional Sigma rules
- UI/UX improvements
- Performance optimizations
- Additional detection engines

---

## 📄 License

Academic Project — For educational use only.

---

## 👤 Author

**Gohar Ali**  
Roll: FA-22-BSDFCS-095  
BS Digital Forensics & Cyber Security  
[University Name]

---

## 🔗 Resources

- [OWASP ModSecurity CRS](https://coreruleset.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
│                   (Live charts, alerts,         │
│                    IP blocking, custody)        │
└─────────────────────────────────────────────────┘
```

---

## Agent Options

| Command | Description |
|---------|-------------|
| `python agent.py --simulate-attacks` | Generate synthetic attack phases live |
| `python agent.py --file access.log --simulate` | Replay file with delay |
| `python agent.py --file access.log --simulate --delay 0.1` | Replay faster |
| `python agent.py --file /var/log/apache2/access.log` | Tail real live log |
| `python agent.py --simulate-attacks --server http://IP:5000` | Remote server |

---

## Project Structure

```
ForensicLogX/
├── app.py                      ← Flask + SocketIO server
├── agent.py                    ← Real-time log streaming agent
├── cli.py                      ← Command-line batch analysis
├── requirements.txt
├── README.md
├── backend/
│   ├── config.py               ← Thresholds & settings
│   ├── parser.py               ← Apache/Nginx log parser
│   ├── realtime_engine.py      ← WebSocket event handler + live detection
│   ├── threat_engine.py        ← Batch threat detection rules
│   ├── integrity.py            ← SHA-256 + Chain of Custody
│   ├── ip_blocker.py           ← Firewall rule generator
│   ├── report_generator.py     ← PDF report (ReportLab)
│   └── routes.py               ← REST API endpoints
├── frontend/
│   ├── templates/index.html    ← Real-time SPA
│   └── static/
│       ├── css/style.css
│       └── js/app.js
├── logs/sample/                ← Sample log files
└── tests/                      ← Unit tests (21 passing)
```

---

## Technologies
- **Backend:** Python 3.10+, Flask, Flask-SocketIO, eventlet, Pandas, ReportLab
- **Agent:** python-socketio[client]
- **Frontend:** HTML5, CSS3, JavaScript ES6, Chart.js, Socket.IO client
- **Forensics:** hashlib SHA-256, iptables/ufw
- **Platform:** Ubuntu 22.04 LTS / Kali Linux
