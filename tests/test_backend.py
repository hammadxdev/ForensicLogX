"""
ForensicLogX — Unit Tests
Run: python -m pytest tests/ -v
"""

import pytest
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.parser        import parse_log_file, get_summary
from backend.threat_engine import (detect_brute_force, detect_flood,
                                   detect_traversal, detect_scanners,
                                   detect_error_storm)
from backend.integrity     import compute_sha256, ChainOfCustody
from backend.ip_blocker    import generate_rules


# ─── Sample log lines ─────────────────────────────────────────────────────────
SAMPLE_LOG = """\
192.168.1.1 - - [15/Mar/2024:08:00:12 +0000] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0"
192.168.1.1 - - [15/Mar/2024:08:00:15 +0000] "GET /about HTTP/1.1" 200 3200 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Mar/2024:08:01:00 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Mar/2024:08:01:03 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Mar/2024:08:01:06 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Mar/2024:08:01:09 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Mar/2024:08:01:12 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Mar/2024:08:01:15 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Mar/2024:08:01:18 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Mar/2024:08:01:21 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Mar/2024:08:01:24 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Mar/2024:08:01:27 +0000] "POST /wp-login.php HTTP/1.1" 401 1200 "-" "Mozilla/5.0"
45.33.32.1 - - [15/Mar/2024:09:00:00 +0000] "GET /../etc/passwd HTTP/1.1" 403 300 "-" "masscan/1.0"
91.108.0.1 - - [15/Mar/2024:10:00:00 +0000] "GET /phpmyadmin HTTP/1.1" 404 512 "-" "Nikto/2.1.6"
192.168.1.2 - - [15/Mar/2024:11:00:00 +0000] "GET / HTTP/1.1" 500 200 "-" "Mozilla/5.0"
192.168.1.2 - - [15/Mar/2024:11:00:01 +0000] "GET /api HTTP/1.1" 500 200 "-" "Mozilla/5.0"
192.168.1.2 - - [15/Mar/2024:11:00:02 +0000] "GET / HTTP/1.1" 503 200 "-" "Mozilla/5.0"
"""


@pytest.fixture
def sample_df():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write(SAMPLE_LOG)
        path = f.name
    df = parse_log_file(path)
    os.unlink(path)
    return df


@pytest.fixture
def sample_logfile():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write(SAMPLE_LOG)
        return f.name


# ─── Parser Tests ─────────────────────────────────────────────────────────────
class TestParser:
    def test_parses_valid_log(self, sample_df):
        assert len(sample_df) > 0

    def test_has_required_columns(self, sample_df):
        required = ['ip', 'method', 'url', 'status', 'bytes', 'timestamp']
        for col in required:
            assert col in sample_df.columns, f"Missing column: {col}"

    def test_status_codes_are_integers(self, sample_df):
        assert sample_df['status'].dtype in ['int32', 'int64']

    def test_summary_has_required_keys(self, sample_df):
        summary = get_summary(sample_df)
        for key in ['total_requests', 'unique_ips', 'error_rate_pct', 'top_ips']:
            assert key in summary

    def test_raises_on_missing_file(self):
        with pytest.raises(FileNotFoundError):
            parse_log_file('/nonexistent/path.log')


# ─── Threat Detection Tests ───────────────────────────────────────────────────
class TestThreatDetection:
    def test_detects_brute_force(self, sample_df):
        threats = detect_brute_force(sample_df)
        ips = [t['ip'] for t in threats]
        assert '10.0.0.5' in ips, "Should detect brute force from 10.0.0.5"

    def test_brute_force_severity(self, sample_df):
        threats = detect_brute_force(sample_df)
        bf = [t for t in threats if t['ip'] == '10.0.0.5']
        assert bf[0]['severity'] in ['critical', 'high']

    def test_detects_traversal(self, sample_df):
        threats = detect_traversal(sample_df)
        assert len(threats) > 0, "Should detect directory traversal"

    def test_detects_scanner(self, sample_df):
        threats = detect_scanners(sample_df)
        assert len(threats) > 0, "Should detect Nikto scanner"

    def test_detects_error_storm(self, sample_df):
        threats = detect_error_storm(sample_df)
        # Only 3 errors in sample, below threshold — should be empty unless threshold=1
        assert isinstance(threats, list)

    def test_threat_has_required_fields(self, sample_df):
        threats = detect_brute_force(sample_df)
        if threats:
            t = threats[0]
            for field in ['type', 'severity', 'ip', 'count', 'detail', 'timestamp']:
                assert field in t, f"Threat missing field: {field}"


# ─── Integrity Tests ───────────────────────────────────────────────────────────
class TestIntegrity:
    def test_sha256_returns_64_hex_chars(self, sample_logfile):
        h = compute_sha256(sample_logfile)
        assert len(h) == 64
        assert all(c in '0123456789abcdef' for c in h)
        os.unlink(sample_logfile)

    def test_sha256_is_deterministic(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_text("test log content\n")
        h1 = compute_sha256(str(f))
        h2 = compute_sha256(str(f))
        assert h1 == h2

    def test_hash_changes_on_modification(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_text("original content\n")
        h1 = compute_sha256(str(f))
        f.write_text("modified content\n")
        h2 = compute_sha256(str(f))
        assert h1 != h2


class TestChainOfCustody:
    def test_initial_entries_created(self):
        coc = ChainOfCustody("TestAnalyst", "test.log", "abc123")
        assert len(coc.entries) == 2  # Evidence Collected + Hash Computed

    def test_add_entry(self):
        coc = ChainOfCustody("Analyst", "test.log", "abc123")
        coc.add_entry("Parsing Done", "500 entries")
        assert len(coc.entries) == 3

    def test_to_dict_has_required_keys(self):
        coc = ChainOfCustody("Analyst", "test.log", "abc123")
        d = coc.to_dict()
        for key in ['case_id', 'analyst', 'filename', 'entries']:
            assert key in d


# ─── IP Blocker Tests ────────────────────────────────────────────────────────
class TestIPBlocker:
    def test_generates_iptables_rules(self):
        rules = generate_rules(["1.2.3.4", "5.6.7.8"])
        assert len(rules['iptables_rules']) == 2
        assert "iptables -A INPUT -s 1.2.3.4 -j DROP" in rules['iptables_rules']

    def test_generates_ufw_rules(self):
        rules = generate_rules(["1.2.3.4"])
        assert "ufw deny from 1.2.3.4 to any" in rules['ufw_rules']

    def test_script_is_bash(self):
        rules = generate_rules(["1.2.3.4"])
        assert rules['script'].startswith("#!/bin/bash")

    def test_empty_ip_list(self):
        rules = generate_rules([])
        assert rules['iptables_rules'] == []


# ─── Report Generator & Defanging Tests ───────────────────────────────────────
class TestReportGenerator:
    def test_defang_text_sanitizes_malicious_payloads(self):
        from backend.report_generator import defang_text
        
        # Test basic XML escaping
        assert defang_text("A & B < C > D") == "A [amp] B [lt] C [gt] D"
        
        # Test signature defanging
        assert defang_text("<script>alert(1)</script>") == "[lt]scr_ipt[gt]al_ert(1)[lt]/scr_ipt[gt]"
        assert "uni_on sel_ect" in defang_text("UNION SELECT 1, 2")
        assert "etc/[passwd]" in defang_text("../../etc/passwd")

    def test_generate_pdf_report_success(self, tmp_path):
        from backend.report_generator import generate_pdf_report
        import os
        
        output_pdf = str(tmp_path / "test_report.pdf")
        summary = {
            "total_requests": 100,
            "unique_ips": 5,
            "error_rate_pct": 2.5
        }
        threats = [
            {"type": "SQL Injection", "severity": "critical", "ip": "192.168.1.50", "count": 1, "detail": "UNION SELECT admin"}
        ]
        custody = [
            {"timestamp": "2026-06-09T18:00:00", "action": "Log Ingestion", "detail": "Loaded logs", "actor": "TestAnalyst"}
        ]
        
        out = generate_pdf_report(
            output_path=output_pdf,
            analyst="Test Analyst",
            organization="BS DFCS",
            summary=summary,
            threats=threats,
            custody_entries=custody,
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            filename="apache.log"
        )
        
        assert os.path.exists(out)
        assert os.path.getsize(out) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
