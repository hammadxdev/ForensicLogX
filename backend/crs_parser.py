"""
ForensicLogX — OWASP ModSecurity CRS Rule Parser
=================================================
Parses all .conf files in dataset/rules/ and extracts rule definitions
into a structured SQLite database and in-memory dictionary.

Rule fields extracted:
    - Rule ID (e.g. 941100)
    - Severity (CRITICAL / HIGH / MEDIUM / LOW / NOTICE)
    - Attack category (XSS, SQLi, LFI, RFI, RCE, etc.)
    - Description (msg field)
    - Detection pattern (@rx / @pm / @detectXSS etc.)
    - Paranoia level (1–4)
    - Tags (OWASP_CRS, attack-xss, capec/...)
    - CAPEC reference
    - CRS version
    - Source file

Usage:
    from backend.crs_parser import CRSParser
    parser = CRSParser()
    count  = parser.load_rules()          # parse + store in SQLite
    rule   = parser.get_rule(941100)      # look up a single rule
    all_r  = parser.get_all_rules()       # return full dict
"""

import os
import re
import json
import sqlite3
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

BASE_DIR   = Path(__file__).resolve().parent.parent          # ForensicLogX/
RULES_DIR  = BASE_DIR / "dataset" / "rules"
DB_PATH    = BASE_DIR / "dataset" / "crs_rules.db"

# Map filename prefix → attack category label
CATEGORY_MAP: Dict[str, str] = {
    "REQUEST-911": "Method Enforcement",
    "REQUEST-913": "Scanner Detection",
    "REQUEST-920": "Protocol Enforcement",
    "REQUEST-921": "Protocol Attack",
    "REQUEST-922": "Multipart Attack",
    "REQUEST-930": "LFI",
    "REQUEST-931": "RFI",
    "REQUEST-932": "RCE",
    "REQUEST-933": "PHP Injection",
    "REQUEST-934": "Generic Injection",
    "REQUEST-941": "XSS",
    "REQUEST-942": "SQLi",
    "REQUEST-943": "Session Fixation",
    "REQUEST-944": "Java Injection",
    "RESPONSE-950": "Data Leakage",
    "RESPONSE-951": "SQL Data Leakage",
    "RESPONSE-952": "Java Data Leakage",
    "RESPONSE-953": "PHP Data Leakage",
    "RESPONSE-954": "IIS Data Leakage",
    "RESPONSE-955": "Web Shell",
    "RESPONSE-956": "Ruby Data Leakage",
}

# Map CRS severity strings → normalised labels
SEVERITY_MAP: Dict[str, str] = {
    "critical": "CRITICAL",
    "error":    "HIGH",
    "warning":  "MEDIUM",
    "notice":   "LOW",
    "info":     "INFO",
    "debug":    "DEBUG",
}

# Paranoia-level tag pattern  e.g. "paranoia-level/2"
_PL_RE = re.compile(r"paranoia-level/(\d)", re.IGNORECASE)

# Match one complete SecRule block (handles line-continuation with \)
_SECRULE_RE = re.compile(
    r'SecRule\s+\S.*?(?<!\\)\n',
    re.DOTALL | re.MULTILINE
)

# Field extractors inside the action string
_ID_RE       = re.compile(r'\bid:(\d+)',            re.IGNORECASE)
_MSG_RE      = re.compile(r"\bmsg:'([^']+)'",       re.IGNORECASE)
_SEV_RE      = re.compile(r"\bseverity:'([^']+)'",  re.IGNORECASE)
_TAG_RE      = re.compile(r"\btag:'([^']+)'",       re.IGNORECASE)
_VER_RE      = re.compile(r"\bver:'([^']+)'",       re.IGNORECASE)
_CAPEC_RE    = re.compile(r"capec/([0-9/]+)",       re.IGNORECASE)
_PATTERN_RE  = re.compile(r'"@(?:rx|pm|detectXSS|detectSQLi|validateByteRange|lt|gt|eq|ge|le|contains|containsWord|endsWith|beginsWith|within|ipMatch)\s*([^"]*)"', re.IGNORECASE)
_OPERATOR_RE = re.compile(r'"(@\w+)',               re.IGNORECASE)


# ─── Database Schema ─────────────────────────────────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS crs_rules (
    rule_id         INTEGER PRIMARY KEY,
    category        TEXT    NOT NULL,
    severity        TEXT    NOT NULL DEFAULT 'MEDIUM',
    description     TEXT,
    pattern         TEXT,
    operator        TEXT,
    paranoia_level  INTEGER DEFAULT 1,
    tags            TEXT,       -- JSON list
    capec           TEXT,
    crs_version     TEXT,
    source_file     TEXT,
    phase           INTEGER DEFAULT 2,
    action          TEXT DEFAULT 'block'
);

CREATE INDEX IF NOT EXISTS idx_crs_category ON crs_rules(category);
CREATE INDEX IF NOT EXISTS idx_crs_severity  ON crs_rules(severity);
CREATE INDEX IF NOT EXISTS idx_crs_pl        ON crs_rules(paranoia_level);
"""


class CRSParser:
    """
    Parse OWASP ModSecurity CRS .conf files and persist rules to SQLite.

    Typical usage::

        parser = CRSParser()
        count  = parser.load_rules()       # parse everything and write to DB
        rule   = parser.get_rule(941100)   # dict or None
        rules  = parser.get_all_rules()    # {rule_id: {...}, ...}
        stats  = parser.get_stats()        # category / severity counts
    """

    def __init__(
        self,
        rules_dir: Optional[str] = None,
        db_path:   Optional[str] = None,
    ) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else RULES_DIR
        self.db_path   = Path(db_path)   if db_path   else DB_PATH
        self._cache: Dict[int, dict] = {}   # in-memory cache after load
        self._ensure_db()

    # ── Public API ────────────────────────────────────────────────────────────

    def load_rules(self, paranoia_level: int = 4) -> int:
        """
        Parse all .conf files and store rules with paranoia_level ≤ *paranoia_level*.
        Returns the number of rules stored.
        """
        logger.info("CRSParser: scanning %s", self.rules_dir)
        all_rules = self._parse_all_files()

        # Filter by paranoia level
        filtered = [r for r in all_rules if r["paranoia_level"] <= paranoia_level]

        self._store_rules(filtered)
        self._cache = {r["rule_id"]: r for r in filtered}

        logger.info("CRSParser: loaded %d rules (PL ≤ %d)", len(filtered), paranoia_level)
        return len(filtered)

    def get_rule(self, rule_id: int) -> Optional[dict]:
        """Return a single rule dict by ID, or None if not found."""
        if self._cache:
            return self._cache.get(rule_id)
        return self._fetch_rule_from_db(rule_id)

    def get_all_rules(self) -> Dict[int, dict]:
        """Return full {rule_id: rule_dict} mapping (uses cache if available)."""
        if self._cache:
            return dict(self._cache)
        return self._fetch_all_from_db()

    def get_rules_by_category(self, category: str) -> List[dict]:
        """Return all rules matching a category (case-insensitive)."""
        return [r for r in self.get_all_rules().values()
                if r["category"].lower() == category.lower()]

    def get_rules_by_severity(self, severity: str) -> List[dict]:
        """Return rules matching a severity level."""
        return [r for r in self.get_all_rules().values()
                if r["severity"].upper() == severity.upper()]

    def get_stats(self) -> dict:
        """Return summary statistics over the loaded rule database."""
        rules = list(self.get_all_rules().values())
        if not rules:
            return {"total": 0}

        from collections import Counter
        cat_counts = Counter(r["category"]   for r in rules)
        sev_counts = Counter(r["severity"]   for r in rules)
        pl_counts  = Counter(r["paranoia_level"] for r in rules)

        return {
            "total":      len(rules),
            "by_category": dict(cat_counts.most_common()),
            "by_severity": dict(sev_counts),
            "by_paranoia": dict(pl_counts),
        }

    # ── File Parsing ─────────────────────────────────────────────────────────

    def _parse_all_files(self) -> List[dict]:
        """Walk the rules directory and parse every .conf file."""
        rules: List[dict] = []
        if not self.rules_dir.exists():
            logger.error("Rules dir not found: %s", self.rules_dir)
            return rules

        conf_files = sorted(self.rules_dir.glob("*.conf"))
        logger.info("CRSParser: found %d .conf files", len(conf_files))

        for conf_file in conf_files:
            if "EXCLUSION" in conf_file.name or "example" in conf_file.name.lower():
                continue  # skip exclusion and example files
            try:
                file_rules = self._parse_file(conf_file)
                rules.extend(file_rules)
                logger.debug("  %s → %d rules", conf_file.name, len(file_rules))
            except Exception as exc:
                logger.warning("  Failed to parse %s: %s", conf_file.name, exc)

        return rules

    def _parse_file(self, path: Path) -> List[dict]:
        """Parse a single .conf file and return a list of rule dicts."""
        category = self._category_from_filename(path.name)
        content  = path.read_text(encoding="utf-8", errors="replace")

        # Join continuation lines (lines ending with \)
        content = self._join_continuation_lines(content)

        rules: List[dict] = []
        # Each SecRule spans one logical line after joining
        for line in content.splitlines():
            line = line.strip()
            if not line.startswith("SecRule"):
                continue
            rule = self._parse_secrule_line(line, category, path.name)
            if rule:
                rules.append(rule)

        return rules

    @staticmethod
    def _join_continuation_lines(text: str) -> str:
        """Replace backslash-newline continuations with a single space."""
        return re.sub(r'\\\n\s*', ' ', text)

    def _parse_secrule_line(self, line: str, category: str, filename: str) -> Optional[dict]:
        """
        Extract fields from a single (joined) SecRule directive.

        A SecRule looks like:
            SecRule VARIABLES "OPERATOR" "id:NNNN,phase:N,block,msg:'...',severity:'...',tag:'...',..."
        """
        # Split into at most 3 parts: keyword, variables, actions_block
        parts = self._split_secrule(line)
        if len(parts) < 2:
            return None

        actions_str = parts[-1] if len(parts) >= 3 else ""
        operator_str = parts[1] if len(parts) >= 2 else ""

        # Extract rule ID — mandatory
        id_m = _ID_RE.search(actions_str)
        if not id_m:
            return None
        rule_id = int(id_m.group(1))

        # Skip meta/control rules (skip, pass, chain-only) — IDs < 900000 or > 999999
        if not (900000 <= rule_id <= 999999):
            return None

        msg_m  = _MSG_RE.search(actions_str)
        sev_m  = _SEV_RE.search(actions_str)
        ver_m  = _VER_RE.search(actions_str)

        description   = msg_m.group(1) if msg_m else ""
        severity_raw  = sev_m.group(1).lower() if sev_m else "notice"
        severity      = SEVERITY_MAP.get(severity_raw, "LOW")
        crs_version   = ver_m.group(1) if ver_m else ""

        tags   = _TAG_RE.findall(actions_str)
        capec  = _CAPEC_RE.search(actions_str)
        capec_str = capec.group(1) if capec else ""

        # Paranoia level from tags
        pl = 1
        for tag in tags:
            pm = _PL_RE.search(tag)
            if pm:
                pl = int(pm.group(1))
                break

        # Detection pattern (first @rx / @pm etc.)
        pat_m = _PATTERN_RE.search(operator_str)
        pattern = pat_m.group(1).strip() if pat_m else ""
        # Operator type
        op_m = _OPERATOR_RE.search(operator_str)
        operator = op_m.group(1) if op_m else ""

        # Phase
        phase_m = re.search(r'\bphase:(\d+)', actions_str)
        phase = int(phase_m.group(1)) if phase_m else 2

        # Action type (block / pass / drop / deny)
        action = "pass"
        for act in ("block", "deny", "drop", "redirect"):
            if re.search(rf'\b{act}\b', actions_str):
                action = act
                break

        return {
            "rule_id":       rule_id,
            "category":      category,
            "severity":      severity,
            "description":   description,
            "pattern":       pattern[:1000],   # cap to avoid huge regexes
            "operator":      operator,
            "paranoia_level": pl,
            "tags":          json.dumps(tags),
            "capec":         capec_str,
            "crs_version":   crs_version,
            "source_file":   filename,
            "phase":         phase,
            "action":        action,
        }

    @staticmethod
    def _split_secrule(line: str) -> List[str]:
        """
        Split a SecRule line into [keyword, variables, actions].
        Respects quoted strings.
        """
        parts = []
        current = []
        in_quote = False
        quote_char = None
        i = 0
        # Skip leading 'SecRule'
        if line.startswith("SecRule"):
            parts.append("SecRule")
            line = line[7:].lstrip()

        while i < len(line):
            c = line[i]
            if in_quote:
                current.append(c)
                if c == quote_char and (i == 0 or line[i-1] != "\\"):
                    in_quote = False
                    quote_char = None
            elif c in ('"', "'"):
                in_quote = True
                quote_char = c
                current.append(c)
            elif c == ' ' and not in_quote:
                part = "".join(current).strip()
                if part:
                    parts.append(part)
                current = []
            else:
                current.append(c)
            i += 1

        remainder = "".join(current).strip()
        if remainder:
            parts.append(remainder)

        return parts

    @staticmethod
    def _category_from_filename(filename: str) -> str:
        """Derive category label from .conf filename prefix."""
        for prefix, cat in CATEGORY_MAP.items():
            if filename.startswith(prefix):
                return cat
        # Fallback: extract from REQUEST-NNN-... pattern
        m = re.match(r'(?:REQUEST|RESPONSE)-\d+-(.+?)\.conf', filename)
        if m:
            return m.group(1).replace("-", " ").title()
        return "Unknown"

    # ── Database Operations ───────────────────────────────────────────────────

    def _ensure_db(self) -> None:
        """Create the SQLite database and schema if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(DDL)
            conn.commit()

    def _store_rules(self, rules: List[dict]) -> None:
        """Upsert rules into the database."""
        if not rules:
            return
        sql = """
        INSERT OR REPLACE INTO crs_rules
            (rule_id, category, severity, description, pattern, operator,
             paranoia_level, tags, capec, crs_version, source_file, phase, action)
        VALUES
            (:rule_id, :category, :severity, :description, :pattern, :operator,
             :paranoia_level, :tags, :capec, :crs_version, :source_file, :phase, :action)
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(sql, rules)
            conn.commit()
        logger.info("CRSParser: stored %d rules in %s", len(rules), self.db_path)

    def _fetch_rule_from_db(self, rule_id: int) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("SELECT * FROM crs_rules WHERE rule_id=?", (rule_id,))
            row = cur.fetchone()
        if row:
            return self._row_to_dict(row)
        return None

    def _fetch_all_from_db(self) -> Dict[int, dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM crs_rules").fetchall()
        return {r["rule_id"]: self._row_to_dict(r) for r in rows}

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        try:
            d["tags"] = json.loads(d.get("tags") or "[]")
        except (json.JSONDecodeError, TypeError):
            d["tags"] = []
        return d


# ─── CLI / Quick Test ─────────────────────────────────────────────────────────

def _example_output(parser: "CRSParser") -> None:
    """Print example output for rule 941100 (XSS via libinjection)."""
    rule = parser.get_rule(941100)
    if rule:
        print("\n=== Rule 941100 ===")
        print(f"  ID          : {rule['rule_id']}")
        print(f"  Category    : {rule['category']}")
        print(f"  Severity    : {rule['severity']}")
        print(f"  Description : {rule['description']}")
        print(f"  Operator    : {rule['operator']}")
        print(f"  Pattern     : {rule['pattern'][:80]}...")
        print(f"  Para Level  : {rule['paranoia_level']}")
        print(f"  Source File : {rule['source_file']}")
        print(f"  CAPEC       : {rule['capec']}")
        print(f"  Tags        : {', '.join(rule['tags'][:5])}")
    else:
        print("Rule 941100 not found — run load_rules() first.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    parser = CRSParser()

    print("Loading CRS rules from:", parser.rules_dir)
    count = parser.load_rules(paranoia_level=2)
    print(f"\nLoaded {count} rules total.")

    stats = parser.get_stats()
    print("\n── Category breakdown ──")
    for cat, n in stats["by_category"].items():
        print(f"  {cat:<30} {n:>5}")

    print("\n── Severity breakdown ──")
    for sev, n in stats["by_severity"].items():
        print(f"  {sev:<12} {n:>5}")

    _example_output(parser)
