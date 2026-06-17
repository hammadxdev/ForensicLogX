# ForensicLogX — Real-Time Linux Log Analyzer
### Final Year Project | BS Digital Forensics & Cyber Security
**Student:** Gohar Ali | **Roll:** FA-22-BSDFCS-095

---

## Quick Start (3 Steps)

### Step 1 — Install
```bash
pip install -r requirements.txt
```

### Step 2 — Start Server
```bash
python app.py
```
Open browser: **http://127.0.0.1:5000**

### Step 3 — Start Agent (new terminal)
```bash
# Best for demo — generates live attack traffic:
python agent.py --simulate-attacks

# OR replay your log file:
python agent.py --file sample_attack_log.log --simulate

# OR tail a real Apache log:
python agent.py --file /var/log/apache2/access.log
```

---

## How It Works

```
┌─────────────────────────────────────────────────┐
│              REAL-TIME FLOW                     │
│                                                 │
│  Log File / Apache   ──►  agent.py              │
│  (tail -f or replay)       │                    │
│                            │ WebSocket          │
│                            ▼                    │
│                      app.py (Flask)             │
│                      realtime_engine.py         │
│                      threat_engine.py           │
│                            │                    │
│                            │ WebSocket broadcast│
│                            ▼                    │
│                   Browser Dashboard             │
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
