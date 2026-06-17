"""
ForensicLogX — CRS API Routes (Blueprint)
==========================================
Registers all /api/crs-* and /api/analyze-* endpoints.

Endpoints:
    POST /api/analyze-log           Analyse a single raw log line
    POST /api/scan-log-file         Batch-analyse a log file (path in body)
    GET  /api/crs-rules             Return loaded rule database
    GET  /api/crs-rules/<rule_id>   Details for a specific rule
    GET  /api/attack-stats          Aggregated detection statistics
    GET  /api/attack-alerts         Recent alerts (paginated)
    POST /api/load-crs              Trigger CRS rule load / reload
    POST /api/parse-modsec          Parse a ModSecurity audit log file
    GET  /api/attack-chains         Detected multi-stage attack chains
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app

logger = logging.getLogger(__name__)

crs_bp = Blueprint("crs", __name__)

# ── Lazy singleton helpers ────────────────────────────────────────────────────
# We defer construction so the heavy CRS parsing happens after first request,
# not at import time (keeps server startup fast).

_detector   = None
_categorizer = None
_parser      = None

def _get_detector():
    global _detector
    if _detector is None:
        from backend.crs_detector import CRSDetector
        _detector = CRSDetector()
        try:
            _detector.load(paranoia_level=2)
        except Exception as e:
            logger.warning("CRS auto-load failed: %s", e)
    return _detector


def _get_categorizer():
    global _categorizer
    if _categorizer is None:
        from backend.attack_categorizer import AttackCategorizer
        _categorizer = AttackCategorizer()
    return _categorizer


def _get_parser():
    global _parser
    if _parser is None:
        from backend.crs_parser import CRSParser
        _parser = CRSParser()
    return _parser


# ═══════════════════════════════════════════════════════════════════════════════
#  CRS RULE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@crs_bp.route("/api/load-crs", methods=["POST"])
def load_crs():
    """
    Parse CRS .conf files and populate the SQLite database.
    Body (optional): { "paranoia_level": 2 }
    """
    data = request.get_json(silent=True) or {}
    pl   = int(data.get("paranoia_level", 2))

    try:
        parser = _get_parser()
        count  = parser.load_rules(paranoia_level=pl)

        # Reload the detector so it picks up new rules
        global _detector
        _detector = None
        det = _get_detector()

        stats = parser.get_stats()
        return jsonify({
            "success":        True,
            "rules_loaded":   count,
            "paranoia_level": pl,
            "stats":          stats,
        })
    except Exception as e:
        logger.exception("load_crs error")
        return jsonify({"error": str(e)}), 500


@crs_bp.route("/api/crs-rules", methods=["GET"])
def get_crs_rules():
    """
    Return the full rule database as a JSON object keyed by rule_id.
    Query params:
        category  — filter by category (e.g. SQLi)
        severity  — filter by severity (CRITICAL / HIGH / MEDIUM / LOW)
        limit     — max rules returned (default 200)
        offset    — pagination offset (default 0)
    """
    parser   = _get_parser()
    category = request.args.get("category", "").strip()
    severity = request.args.get("severity", "").strip()
    limit    = int(request.args.get("limit",  200))
    offset   = int(request.args.get("offset", 0))

    try:
        all_rules = parser.get_all_rules()
        rules = list(all_rules.values())

        if category:
            rules = [r for r in rules if r["category"].lower() == category.lower()]
        if severity:
            rules = [r for r in rules if r["severity"].upper() == severity.upper()]

        total = len(rules)
        page  = rules[offset: offset + limit]

        return jsonify({
            "total":  total,
            "offset": offset,
            "limit":  limit,
            "rules":  page,
        })
    except Exception as e:
        logger.exception("get_crs_rules error")
        return jsonify({"error": str(e)}), 500


@crs_bp.route("/api/crs-rules/<int:rule_id>", methods=["GET"])
def get_crs_rule(rule_id: int):
    """Return details for a single CRS rule."""
    parser = _get_parser()
    rule   = parser.get_rule(rule_id)
    if not rule:
        return jsonify({"error": f"Rule {rule_id} not found"}), 404

    # Enrich with MITRE data
    cat  = _get_categorizer()
    mitre = cat._lookup_mitre(rule_id)

    return jsonify({**rule, "mitre": mitre})


# ═══════════════════════════════════════════════════════════════════════════════
#  LOG ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

@crs_bp.route("/api/analyze-log", methods=["POST"])
def analyze_log():
    """
    Analyse a single raw log line.
    Body: { "line": "192.168.1.50 - - [05/May/2026...] ..." }
    Returns list of alert dicts.
    """
    data = request.get_json(silent=True)
    if not data or "line" not in data:
        return jsonify({"error": "Missing 'line' field"}), 400

    raw_line = data["line"]
    save     = bool(data.get("save", True))

    try:
        detector = _get_detector()
        alerts   = detector.analyze_line(raw_line, save=save)

        cat      = _get_categorizer()
        enriched = cat.enrich_batch(alerts)

        return jsonify({
            "line":        raw_line[:200],
            "alert_count": len(enriched),
            "alerts":      enriched,
        })
    except Exception as e:
        logger.exception("analyze_log error")
        return jsonify({"error": str(e)}), 500


@crs_bp.route("/api/scan-log-file", methods=["POST"])
def scan_log_file():
    """
    Batch-analyse an entire log file on the server.
    Body: { "filepath": "/path/to/access.log", "save": true, "paranoia_level": 2 }
    """
    data = request.get_json(silent=True)
    if not data or "filepath" not in data:
        return jsonify({"error": "Missing 'filepath' field"}), 400

    filepath = data["filepath"]
    save     = bool(data.get("save", True))
    pl       = int(data.get("paranoia_level", 2))

    if not Path(filepath).exists():
        return jsonify({"error": f"File not found: {filepath}"}), 404

    try:
        detector = _get_detector()
        alerts   = detector.analyze_file(filepath, save=save, paranoia_level=pl)

        cat      = _get_categorizer()
        enriched = cat.enrich_batch(alerts)
        chains   = cat.detect_chains(alerts)
        campaigns = cat.summarise_by_ip(alerts)

        return jsonify({
            "filepath":     filepath,
            "total_alerts": len(enriched),
            "chains":       chains,
            "campaigns":    campaigns[:20],
            "alerts":       enriched[:500],   # cap payload size
        })
    except Exception as e:
        logger.exception("scan_log_file error")
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  STATISTICS & ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

@crs_bp.route("/api/attack-stats", methods=["GET"])
def attack_stats():
    """Return aggregated detection statistics from the alerts database."""
    try:
        detector = _get_detector()
        stats    = detector.get_attack_stats()
        return jsonify(stats)
    except Exception as e:
        logger.exception("attack_stats error")
        return jsonify({"error": str(e)}), 500


@crs_bp.route("/api/attack-alerts", methods=["GET"])
def attack_alerts():
    """
    Return recent alerts (paginated).
    Query params: limit (default 50)
    """
    limit = int(request.args.get("limit", 50))
    try:
        detector = _get_detector()
        alerts   = detector.get_recent_alerts(limit=limit)
        return jsonify({
            "count":  len(alerts),
            "alerts": alerts,
        })
    except Exception as e:
        logger.exception("attack_alerts error")
        return jsonify({"error": str(e)}), 500


@crs_bp.route("/api/attack-chains", methods=["GET"])
def attack_chains():
    """Return recently detected multi-stage attack chains."""
    limit = int(request.args.get("limit", 100))
    try:
        detector = _get_detector()
        alerts   = detector.get_recent_alerts(limit=limit)
        cat      = _get_categorizer()
        chains   = cat.detect_chains(alerts, window_seconds=600)
        campaigns = cat.summarise_by_ip(alerts)
        return jsonify({
            "chains":    chains,
            "campaigns": campaigns,
        })
    except Exception as e:
        logger.exception("attack_chains error")
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  MODSECURITY AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════════

@crs_bp.route("/api/parse-modsec", methods=["POST"])
def parse_modsec():
    """
    Parse a ModSecurity audit log file.
    Body: { "filepath": "/var/log/apache2/modsec_audit.log" }
    """
    data = request.get_json(silent=True)
    if not data or "filepath" not in data:
        return jsonify({"error": "Missing 'filepath' field"}), 400

    filepath = data["filepath"]
    if not Path(filepath).exists():
        return jsonify({"error": f"File not found: {filepath}"}), 404

    try:
        from backend.modsec_log_parser import ModSecParser
        from backend.crs_parser import CRSParser

        parser_obj = CRSParser()
        crs_rules  = parser_obj.get_all_rules()

        modsec = ModSecParser(crs_rules=crs_rules)
        txns   = modsec.parse_file(filepath)
        alerts = modsec.to_detector_alerts(txns)

        cat      = _get_categorizer()
        enriched = cat.enrich_batch(alerts)
        chains   = cat.detect_chains(alerts)

        return jsonify({
            "filepath":           filepath,
            "transactions_parsed": len(txns),
            "total_alerts":       len(enriched),
            "chains":             chains,
            "alerts":             enriched[:200],
        })
    except Exception as e:
        logger.exception("parse_modsec error")
        return jsonify({"error": str(e)}), 500
