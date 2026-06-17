"""
ForensicLogX — False Positive Handler
Provides allowlists (RFC-1918 IPs, search engine bots, health checks) 
and handles updating the false positive status of detected alerts.
"""

import sqlite3
import ipaddress
import re
from backend.crs_parser import DB_PATH

# Search engine bots regular expression
BOT_RE = re.compile(r"(?i)(googlebot|bingbot|yandexbot|baiduspider|duckduckbot|slurp|twitterbot|facebookexternalhit)")

# Static files and health check paths that frequently cause false positives
STATIC_OR_HEALTH_PATHS = re.compile(r"(?i)\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot)$|^/(health|status|ping|live|ready)$")

class FalsePositiveHandler:
    @staticmethod
    def is_rfc1918_ip(ip: str) -> bool:
        """Check if an IP address belongs to RFC-1918 private space or localhost."""
        if not ip:
            return False
        # Remove port if present
        ip = ip.split(":")[0]
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            return False

    @staticmethod
    def is_legitimate_bot(user_agent: str) -> bool:
        """Check if the user-agent matches known search engine bots."""
        if not user_agent:
            return False
        return bool(BOT_RE.search(user_agent))

    @staticmethod
    def is_static_or_health_path(url: str) -> bool:
        """Check if the path is a static asset or a health check endpoint."""
        if not url:
            return False
        # Remove query parameters
        path = url.split("?")[0]
        return bool(STATIC_OR_HEALTH_PATHS.search(path))

    def adjust_confidence(self, base_confidence: int, ip: str, user_agent: str, url: str) -> int:
        """
        Calculate adjusted confidence score based on request context.
        Lowers the score for typical FP-prone requests.
        """
        score = base_confidence

        # 1. Private IP check (internal traffic is less likely to be malicious external scans)
        if self.is_rfc1918_ip(ip):
            score -= 20

        # 2. Known web crawler checks (crawlers look like directory enumerators or scanner bots)
        if self.is_legitimate_bot(user_agent):
            score -= 30

        # 3. Static assets / health check paths
        if self.is_static_or_health_path(url):
            score -= 25

        # Clamp score between 1 and 100
        return max(1, min(100, score))

    def evaluate_alert(self, rule_id: str, base_confidence: int, ip: str, user_agent: str, url: str) -> dict:
        """
        Evaluate alert context to compute confidence score and recommend if it should be marked FP automatically.
        """
        confidence = self.adjust_confidence(base_confidence, ip, user_agent, url)
        
        # Decide if it's an automatic false positive (confidence falls below threshold)
        is_fp = False
        reason = ""
        
        if confidence <= 30:
            is_fp = True
            reasons = []
            if self.is_rfc1918_ip(ip):
                reasons.append("Internal RFC-1918 IP source")
            if self.is_legitimate_bot(user_agent):
                reasons.append("Legitimate Search Bot Crawler")
            if self.is_static_or_health_path(url):
                reasons.append("Static Asset or Health Check route")
            reason = "Auto-flagged: " + " & ".join(reasons)

        return {
            "confidence_score": confidence,
            "false_positive_flag": 1 if is_fp else 0,
            "reason": reason
        }

    def mark_fp(self, attack_id: int) -> bool:
        """Set the false_positive_flag for a given attack in the database."""
        sql_update_attack = "UPDATE detected_attacks SET false_positive_flag = 1, confidence_score = 5 WHERE id = ?"
        sql_get_rule = "SELECT rule_id FROM detected_attacks WHERE id = ?"
        sql_update_stats = """
            INSERT INTO detection_rule_stats (rule_id, fp_count) 
            VALUES (?, 1)
            ON CONFLICT(rule_id) DO UPDATE SET fp_count = fp_count + 1
        """
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(sql_update_attack, (attack_id,))
                
                # Fetch associated rule_id to increment rule stats
                cursor.execute(sql_get_rule, (attack_id,))
                row = cursor.fetchone()
                if row and row[0]:
                    rule_id = str(row[0])
                    cursor.execute(sql_update_stats, (rule_id,))
                
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error marking attack as false positive: {e}")
            return False

    def get_fp_stats(self) -> list[dict]:
        """Fetch false positive count vs total alerts per rule/attack type."""
        sql = """
            SELECT 
                category,
                COUNT(*) as total_alerts,
                SUM(CASE WHEN false_positive_flag = 1 THEN 1 ELSE 0 END) as fp_alerts
            FROM detected_attacks
            GROUP BY category
        """
        stats = []
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(sql).fetchall()
                for r in rows:
                    stats.append({
                        "category": r["category"],
                        "total_alerts": r["total_alerts"],
                        "fp_alerts": r["fp_alerts"],
                        "fp_rate": round((r["fp_alerts"] / r["total_alerts"]) * 100, 2) if r["total_alerts"] > 0 else 0.0
                    })
        except Exception as e:
            print(f"Error fetching false positive statistics: {e}")
        return stats
