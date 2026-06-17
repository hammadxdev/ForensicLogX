"""
ForensicLogX — Configuration
"""
import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "forensiclogx-fyp-secret-2024")
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "..", "uploads")
    REPORT_FOLDER = os.path.join(os.path.dirname(__file__), "..", "reports")
    HASH_FOLDER   = os.path.join(os.path.dirname(__file__), "..", "hashes")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB
    ALLOWED_EXTENSIONS = {"log", "txt"}

    # Threat detection thresholds
    BRUTE_FORCE_THRESHOLD    = 10
    FLOOD_THRESHOLD          = 50
    TRAVERSAL_PATTERNS       = ["../", "..\\", "etc/passwd", ".git", "web.config", "wp-config"]
    SCANNER_AGENTS           = ["Nikto", "masscan", "sqlmap", "nmap", "zgrab",
                                 "dirbuster", "wfuzz", "gobuster", "nuclei", "hydra"]
    ERROR_STORM_THRESHOLD    = 20
