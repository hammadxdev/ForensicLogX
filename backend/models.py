"""
ForensicLogX — SQLAlchemy ORM Models (CRS + Attack tables)
===========================================================
Two model groups:
  1. CRS rule metadata (CRSRule)
  2. Detected attacks / alerts (DetectedAttack)

These are used for type-safe ORM access and report generation.
The raw SQLite tables are also maintained directly by crs_parser.py and
crs_detector.py for performance (no ORM overhead in hot paths).

Usage::
    from backend.models import Session, CRSRule, DetectedAttack, init_db
    init_db()   # creates tables if they don't exist

    with Session() as s:
        rules = s.query(CRSRule).filter_by(category="SQLi").all()
        attacks = s.query(DetectedAttack).order_by(DetectedAttack.id.desc()).limit(50).all()
"""

import os
import json
from datetime import datetime
from pathlib import Path

# SQLAlchemy — optional dependency; gracefully degrade if not installed
try:
    from sqlalchemy import (
        create_engine, Column, Integer, String, Boolean, Text,
        DateTime, ForeignKey, Index, event
    )
    from sqlalchemy.orm import (
        declarative_base, relationship, sessionmaker, Session as _Session
    )
    _SQLALCHEMY_AVAILABLE = True
except ImportError:
    _SQLALCHEMY_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH  = BASE_DIR / "dataset" / "crs_rules.db"
DB_URL   = f"sqlite:///{DB_PATH}"

if _SQLALCHEMY_AVAILABLE:
    Base    = declarative_base()
    _engine = None

    def get_engine():
        global _engine
        if _engine is None:
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            _engine = create_engine(
                DB_URL,
                connect_args={"check_same_thread": False},
                echo=False,
            )
            # Enable WAL for better concurrent read performance
            @event.listens_for(_engine, "connect")
            def _set_wal(dbapi_connection, connection_record):
                dbapi_connection.execute("PRAGMA journal_mode=WAL")
                dbapi_connection.execute("PRAGMA foreign_keys=ON")
        return _engine

    Session = sessionmaker(bind=None)   # bound lazily in init_db()

    # ── CRS Rule Model ────────────────────────────────────────────────────────

    class CRSRule(Base):
        """
        Mirrors the crs_rules table created by CRSParser.

        Attributes
        ----------
        rule_id        : Official CRS rule number (e.g. 941100)
        category       : Attack family (XSS, SQLi, LFI, RCE, …)
        severity       : CRITICAL / HIGH / MEDIUM / LOW
        description    : Human-readable rule description (msg field)
        pattern        : Detection pattern string (@rx expression)
        operator       : ModSecurity operator type (@rx, @pm, @detectXSS, …)
        paranoia_level : 1–4 (higher = more aggressive)
        tags           : JSON-encoded list of CRS tags
        capec          : CAPEC reference string
        crs_version    : CRS version string (e.g. 'OWASP_CRS/4.27.0-dev')
        source_file    : .conf filename the rule came from
        phase          : ModSecurity processing phase (1 or 2)
        action         : Default action (block / pass / deny / drop)
        """

        __tablename__ = "crs_rules"

        rule_id         = Column(Integer,  primary_key=True)
        category        = Column(String(64),  nullable=False, index=True)
        severity        = Column(String(16),  nullable=False, default="MEDIUM", index=True)
        description     = Column(Text)
        pattern         = Column(Text)
        operator        = Column(String(32))
        paranoia_level  = Column(Integer, default=1, index=True)
        tags            = Column(Text)          # JSON list stored as TEXT
        capec           = Column(String(64))
        crs_version     = Column(String(64))
        source_file     = Column(String(128))
        phase           = Column(Integer, default=2)
        action          = Column(String(16), default="block")

        # Relationship back to detected attacks
        attacks = relationship("DetectedAttack", back_populates="rule",
                               foreign_keys="DetectedAttack.rule_id")

        # ── Helpers ───────────────────────────────────────────────────────────

        @property
        def tags_list(self):
            """Return tags as a Python list."""
            try:
                return json.loads(self.tags or "[]")
            except (json.JSONDecodeError, TypeError):
                return []

        def to_dict(self) -> dict:
            return {
                "rule_id":        self.rule_id,
                "category":       self.category,
                "severity":       self.severity,
                "description":    self.description,
                "operator":       self.operator,
                "paranoia_level": self.paranoia_level,
                "tags":           self.tags_list,
                "capec":          self.capec,
                "crs_version":    self.crs_version,
                "source_file":    self.source_file,
                "phase":          self.phase,
                "action":         self.action,
            }

        def __repr__(self) -> str:
            return f"<CRSRule id={self.rule_id} cat={self.category} sev={self.severity}>"

    # ── Detected Attack Model ─────────────────────────────────────────────────

    class DetectedAttack(Base):
        """
        Stores each CRS-matched attack event.

        Attributes
        ----------
        id              : Auto-increment primary key
        timestamp       : ISO-8601 UTC detection time
        source_ip       : Attacker IP address
        rule_id         : FK → CRSRule.rule_id (nullable for heuristic hits)
        category        : Attack category (de-normalised for query speed)
        severity        : Alert severity (de-normalised)
        description     : Rule description at time of detection
        matched_pattern : Exact text that triggered the rule
        method          : HTTP method (GET, POST, …)
        url             : Requested URL
        status_code     : HTTP response status
        user_agent      : Requesting user-agent header
        log_line        : Full original log line
        blocked         : True if the anomaly score exceeded blocking threshold
        log_source      : Log source (apache_access, syslog, auth_log, etc.)
        attack_type     : Attack type classification
        recommendation  : Recommended remediation action
        """

        __tablename__ = "detected_attacks"

        id              = Column(Integer, primary_key=True, autoincrement=True)
        timestamp       = Column(String(32),  nullable=False, index=True,
                                 default=lambda: datetime.utcnow().isoformat() + "Z")
        source_ip       = Column(String(45),  index=True)
        rule_id         = Column(Integer, ForeignKey("crs_rules.rule_id",
                                                     ondelete="SET NULL"),
                                 nullable=True, index=True)
        category        = Column(String(64),  index=True)
        severity        = Column(String(16),  index=True)
        description     = Column(Text)
        matched_pattern = Column(Text)
        method          = Column(String(16))
        url             = Column(Text)
        status_code     = Column(Integer)
        user_agent      = Column(Text)
        log_line        = Column(Text)
        blocked         = Column(Boolean, default=False)
        log_source      = Column(String(64))
        attack_type     = Column(String(64))
        recommendation  = Column(Text)
        confidence_score = Column(Integer, default=50)
        false_positive_flag = Column(Integer, default=0, index=True)
        mitre_technique_id = Column(Text)
        mitre_tactic        = Column(Text)
        threshold_config    = Column(Text)
        ioc_matched         = Column(Text)

        # Relationship
        rule = relationship("CRSRule", back_populates="attacks",
                            foreign_keys=[rule_id])

        # Additional composite indexes
        __table_args__ = (
            Index("idx_da_ip_ts",  "source_ip",  "timestamp"),
            Index("idx_da_sev_ts", "severity",   "timestamp"),
        )

        def to_dict(self) -> dict:
            return {
                "id":              self.id,
                "timestamp":       self.timestamp,
                "source_ip":       self.source_ip,
                "rule_id":         self.rule_id,
                "category":        self.category,
                "severity":        self.severity,
                "description":     self.description,
                "matched_pattern": self.matched_pattern,
                "method":          self.method,
                "url":             self.url,
                "status_code":     self.status_code,
                "user_agent":      self.user_agent,
                "log_line":        self.log_line,
                "blocked":         self.blocked,
                "log_source":      self.log_source,
                "attack_type":     self.attack_type,
                "recommendation":  self.recommendation,
                "confidence_score": self.confidence_score,
                "false_positive_flag": self.false_positive_flag,
                "mitre_technique_id": self.mitre_technique_id,
                "mitre_tactic":       self.mitre_tactic,
                "threshold_config":    self.threshold_config,
                "ioc_matched":         self.ioc_matched,
            }

        def __repr__(self) -> str:
            return (
                f"<DetectedAttack id={self.id} rule={self.rule_id} "
                f"ip={self.source_ip} sev={self.severity}>"
            )

    # ── Raw Logs Model ────────────────────────────────────────────────────────

    class RawLog(Base):
        __tablename__ = "raw_logs"
        id          = Column(Integer, primary_key=True, autoincrement=True)
        timestamp   = Column(String(32), index=True)
        hostname    = Column(String(128))
        agent_id    = Column(String(64))
        log_source  = Column(String(64))
        raw_log     = Column(Text)

    # ── Parsed Web Logs Model ─────────────────────────────────────────────────

    class ParsedWebLog(Base):
        __tablename__ = "parsed_web_logs"
        id          = Column(Integer, primary_key=True, autoincrement=True)
        timestamp   = Column(String(32), index=True)
        source_ip   = Column(String(45), index=True)
        method      = Column(String(16))
        url         = Column(Text)
        status_code = Column(Integer)
        user_agent  = Column(Text)
        log_source  = Column(String(64))
        raw_log     = Column(Text)

    # ── ModSecurity Alerts Model ──────────────────────────────────────────────

    class ModSecurityAlert(Base):
        __tablename__ = "modsecurity_alerts"
        id              = Column(Integer, primary_key=True, autoincrement=True)
        timestamp       = Column(String(32), index=True)
        source_ip       = Column(String(45), index=True)
        method          = Column(String(16))
        url             = Column(Text)
        status_code     = Column(Integer)
        rule_id         = Column(Integer, index=True)
        rule_message    = Column(Text)
        severity        = Column(String(16))
        attack_category = Column(String(64))
        blocked         = Column(Boolean, default=False)
        transaction_id  = Column(String(64))
        raw_log         = Column(Text)

    # ── Attacker IPs Model ─────────────────────────────────────────────────────

    class AttackerIP(Base):
        __tablename__ = "attacker_ips"
        id           = Column(Integer, primary_key=True, autoincrement=True)
        ip           = Column(String(45), unique=True, index=True)
        attack_count = Column(Integer, default=0)
        first_seen   = Column(String(32))
        last_seen    = Column(String(32))
        blocked      = Column(Boolean, default=False)

    class DetectionRuleStats(Base):
        __tablename__ = "detection_rule_stats"
        rule_id     = Column(String(64), primary_key=True)
        hit_count   = Column(Integer, default=0)
        fp_count    = Column(Integer, default=0)
        last_hit    = Column(String(32))
        avg_confidence = Column(Integer, default=0)

    class ForensicAnalysis(Base):
        __tablename__ = "forensic_analysis"
        id           = Column(String(64), primary_key=True)
        timestamp    = Column(String(32), nullable=False, default=lambda: datetime.utcnow().isoformat() + "Z")
        filename     = Column(String(256))
        file_hash    = Column(String(64))
        analyst      = Column(String(128))
        organization = Column(String(256))
        summary      = Column(Text)   # JSON string
        threats      = Column(Text)   # JSON string
        custody      = Column(Text)   # JSON string
        filepath     = Column(Text)

        def to_dict(self) -> dict:
            return {
                "id":           self.id,
                "timestamp":    self.timestamp,
                "filename":     self.filename,
                "file_hash":    self.file_hash,
                "analyst":      self.analyst,
                "organization": self.organization,
                "summary":      json.loads(self.summary or "{}"),
                "threats":      json.loads(self.threats or "[]"),
                "custody":      json.loads(self.custody or "[]"),
                "filepath":     self.filepath
            }

    # ── DB Initialisation ─────────────────────────────────────────────────────

    def init_db() -> None:
        """Create all tables and bind the Session factory."""
        engine = get_engine()
        Base.metadata.create_all(engine)
        Session.configure(bind=engine)

    def ensure_all_tables() -> None:
        """Raw SQLite table creation to ensure all tables exist under SQLite directly."""
        import sqlite3
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        
        # SQL statements for creation
        ddl = """
        CREATE TABLE IF NOT EXISTS raw_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            hostname TEXT,
            agent_id TEXT,
            log_source TEXT,
            raw_log TEXT
        );

        CREATE TABLE IF NOT EXISTS parsed_web_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            method TEXT,
            url TEXT,
            status_code INTEGER,
            user_agent TEXT,
            log_source TEXT,
            raw_log TEXT
        );

        CREATE TABLE IF NOT EXISTS modsecurity_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            method TEXT,
            url TEXT,
            status_code INTEGER,
            rule_id INTEGER,
            rule_message TEXT,
            severity TEXT,
            attack_category TEXT,
            blocked INTEGER,
            transaction_id TEXT,
            raw_log TEXT
        );

        CREATE TABLE IF NOT EXISTS attacker_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            attack_count INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            blocked INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS detection_rule_stats (
            rule_id TEXT PRIMARY KEY,
            hit_count INTEGER DEFAULT 0,
            fp_count INTEGER DEFAULT 0,
            last_hit TEXT,
            avg_confidence REAL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS detected_attacks (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            source_ip       TEXT,
            rule_id         INTEGER,
            category        TEXT,
            severity        TEXT,
            description     TEXT,
            matched_pattern TEXT,
            method          TEXT,
            url             TEXT,
            status_code     INTEGER,
            user_agent      TEXT,
            log_line        TEXT,
            blocked         INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS forensic_analysis (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            filename TEXT,
            file_hash TEXT,
            analyst TEXT,
            organization TEXT,
            summary TEXT,
            threats TEXT,
            custody TEXT,
            filepath TEXT
        );
        """
        with sqlite3.connect(DB_PATH) as conn:
            conn.executescript(ddl)
            
            # Create view for detection_rules mapping to crs_rules
            conn.execute("DROP VIEW IF EXISTS detection_rules;")
            conn.execute("CREATE VIEW detection_rules AS SELECT * FROM crs_rules;")
            
            # Alter detected_attacks to add columns if missing
            columns_to_add = [
                ("log_source", "TEXT"), 
                ("attack_type", "TEXT"), 
                ("recommendation", "TEXT"),
                ("confidence_score", "INTEGER DEFAULT 50"),
                ("false_positive_flag", "INTEGER DEFAULT 0"),
                ("mitre_technique_id", "TEXT"),
                ("mitre_tactic", "TEXT"),
                ("threshold_config", "TEXT"),
                ("ioc_matched", "TEXT")
            ]
            for col in columns_to_add:
                try:
                    conn.execute(f"ALTER TABLE detected_attacks ADD COLUMN {col[0]} {col[1]};")
                except sqlite3.OperationalError:
                    # Column already exists
                    pass
            
            conn.commit()

else:
    # ── Stub models when SQLAlchemy is not installed ──────────────────────────

    class CRSRule:          # type: ignore[no-redef]
        pass

    class DetectedAttack:   # type: ignore[no-redef]
        pass

    class ForensicAnalysis: # type: ignore[no-redef]
        pass

    class Session:          # type: ignore[no-redef]
        def __enter__(self): return self
        def __exit__(self, *a): pass

    def init_db() -> None:
        pass

    def get_engine():
        return None

    def ensure_all_tables() -> None:
        import sqlite3
        from pathlib import Path
        db_p = Path(__file__).resolve().parent.parent / "dataset" / "crs_rules.db"
        db_p.parent.mkdir(parents=True, exist_ok=True)
        # raw creation logic above
        ddl = """
        CREATE TABLE IF NOT EXISTS raw_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            hostname TEXT,
            agent_id TEXT,
            log_source TEXT,
            raw_log TEXT
        );

        CREATE TABLE IF NOT EXISTS parsed_web_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            method TEXT,
            url TEXT,
            status_code INTEGER,
            user_agent TEXT,
            log_source TEXT,
            raw_log TEXT
        );

        CREATE TABLE IF NOT EXISTS modsecurity_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            method TEXT,
            url TEXT,
            status_code INTEGER,
            rule_id INTEGER,
            rule_message TEXT,
            severity TEXT,
            attack_category TEXT,
            blocked INTEGER,
            transaction_id TEXT,
            raw_log TEXT
        );

        CREATE TABLE IF NOT EXISTS attacker_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            attack_count INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            blocked INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS detection_rule_stats (
            rule_id TEXT PRIMARY KEY,
            hit_count INTEGER DEFAULT 0,
            fp_count INTEGER DEFAULT 0,
            last_hit TEXT,
            avg_confidence REAL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS detected_attacks (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            source_ip       TEXT,
            rule_id         INTEGER,
            category        TEXT,
            severity        TEXT,
            description     TEXT,
            matched_pattern TEXT,
            method          TEXT,
            url             TEXT,
            status_code     INTEGER,
            user_agent      TEXT,
            log_line        TEXT,
            blocked         INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS forensic_analysis (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            filename TEXT,
            file_hash TEXT,
            analyst TEXT,
            organization TEXT,
            summary TEXT,
            threats TEXT,
            custody TEXT,
            filepath TEXT
        );
        """
        with sqlite3.connect(db_p) as conn:
            conn.executescript(ddl)
            conn.execute("DROP VIEW IF EXISTS detection_rules;")
            conn.execute("CREATE VIEW detection_rules AS SELECT * FROM crs_rules;")
            columns_to_add = [
                ("log_source", "TEXT"), 
                ("attack_type", "TEXT"), 
                ("recommendation", "TEXT"),
                ("confidence_score", "INTEGER DEFAULT 50"),
                ("false_positive_flag", "INTEGER DEFAULT 0"),
                ("mitre_technique_id", "TEXT"),
                ("mitre_tactic", "TEXT"),
                ("threshold_config", "TEXT"),
                ("ioc_matched", "TEXT")
            ]
            for col in columns_to_add:
                try:
                    conn.execute(f"ALTER TABLE detected_attacks ADD COLUMN {col[0]} {col[1]};")
                except sqlite3.OperationalError:
                    pass
            conn.commit()

