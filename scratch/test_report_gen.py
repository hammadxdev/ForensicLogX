import sys
import os

# Add root directory to python path
sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/..'))

from backend.report_generator import generate_pdf_report

summary = {
    'total_requests': 875,
    'unique_ips': 10,
    'error_rate_pct': 20.6,
    'bytes_total': 18432000
}

threats = [
    {"type": "Brute Force", "severity": "critical", "ip": "185.220.101.34", "count": 84, "detail": "84 auth failures from 185.220.101.34"},
    {"type": "HTTP Flood / DDoS", "severity": "high", "ip": "91.108.4.180", "count": 65, "detail": "65 req/min — possible DDoS"},
    {"type": "Directory Traversal", "severity": "high", "ip": "45.33.32.156", "count": 15, "detail": "Path traversal: /../etc/passwd"},
    {"type": "Vulnerability Scanner", "severity": "medium", "ip": "91.108.4.180", "count": 30, "detail": "Scanner: Nikto — 30 requests"},
    {"type": "Weak Session IDs", "severity": "medium", "ip": "10.0.0.22", "count": 42, "detail": "Predictable session token sequence"}
]

custody = [
    {"timestamp": "2024-03-15T10:00:00", "action": "Evidence Collected", "detail": "demo_apache_access.log", "actor": "Gohar Ali"},
    {"timestamp": "2024-03-15T10:00:01", "action": "Hash Computed", "detail": "SHA-256: a3f8c2d91e4b...", "actor": "System"},
    {"timestamp": "2024-03-15T10:00:02", "action": "Log Ingestion Complete", "detail": "875 lines processed", "actor": "System"},
    {"timestamp": "2024-03-15T10:00:03", "action": "Threat Intel Correlated", "detail": "5 alerts triggered", "actor": "System"}
]

os.makedirs('scratch', exist_ok=True)
out = generate_pdf_report(
    output_path="scratch/test_report.pdf",
    analyst="Gohar Ali",
    organization="BS Digital Forensics & Cyber Security",
    summary=summary,
    threats=threats,
    custody_entries=custody,
    file_hash="a3f8c2d91e4b7f0612a85c3d9e2f1b4a7c0d3e6f8a1b4c7d0e3f6a9b2c5d8e1f",
    filename="demo_apache_access.log"
)

print("PDF compilation successful! Output saved at:", os.path.abspath(out))
print("File size:", os.path.getsize(out), "bytes")
