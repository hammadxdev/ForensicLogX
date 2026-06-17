"""
ForensicLogX — Log Parser Module
Parses Apache Combined Log Format and Nginx Default Log Format
into a unified pandas DataFrame.
"""

import re
import pandas as pd
from datetime import datetime
import os

# ─── Apache Combined Log Format ───────────────────────────────────────────────
# Example:
# 192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref.com/" "Mozilla/5.0"
APACHE_PATTERN = re.compile(
    r'(?:(?P<vhost>\S+)\s+)?'   # optional virtual host
    r'(?P<ip>\S+)\s+'          # IP address
    r'\S+\s+'                   # ident (usually -)
    r'(?P<user>\S+)\s+'        # auth user
    r'\[(?P<time>[^\]]+)\]\s+' # timestamp
    r'"(?P<method>\S+)\s+'     # HTTP method
    r'(?P<url>\S+)\s+'         # URL
    r'(?P<proto>[^"]+)"\s+'    # protocol
    r'(?P<status>\d{3})\s+'    # status code
    r'(?P<bytes>\S+)'           # bytes
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'  # optional referer + UA
)

# ─── Nginx Default Log Format ─────────────────────────────────────────────────
# Example:
# 127.0.0.1 - - [20/May/2024:10:00:00 +0500] "GET / HTTP/1.1" 200 612 "-" "curl/7.68.0"
NGINX_PATTERN = APACHE_PATTERN  # Nginx default format is same as Apache combined

APACHE_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_line(line: str) -> dict | None:
    """Parse a single log line. Returns dict or None if malformed."""
    line = line.strip()
    if not line:
        return None

    match = APACHE_PATTERN.match(line)
    if not match:
        return None

    d = match.groupdict()

    # Parse timestamp
    try:
        ts = datetime.strptime(d["time"], APACHE_TIME_FORMAT)
    except ValueError:
        try:
            ts = datetime.strptime(d["time"].rsplit(" ", 1)[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None

    # Parse bytes
    try:
        byte_count = int(d["bytes"]) if d["bytes"] != "-" else 0
    except ValueError:
        byte_count = 0

    return {
        "timestamp":  ts,
        "ip":         d.get("ip", "-"),
        "user":       d.get("user", "-"),
        "method":     d.get("method", "-"),
        "url":        d.get("url", "-"),
        "protocol":   d.get("proto", "HTTP/1.1").strip(),
        "status":     int(d.get("status", 0)),
        "bytes":      byte_count,
        "referer":    d.get("referer") or "-",
        "user_agent": d.get("agent") or "-",
        "raw":        line,
    }


def parse_log_file(filepath: str) -> pd.DataFrame:
    """
    Read a log file and return a cleaned pandas DataFrame.
    Handles large files efficiently using chunked reading.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    records = []
    malformed = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parsed = _parse_line(line)
            if parsed:
                records.append(parsed)
            else:
                malformed += 1

    if not records:
        raise ValueError("No valid log entries found. Check log format (Apache/Nginx combined).")

    df = pd.DataFrame(records)
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    # Derived columns
    df["hour"]        = df["timestamp"].dt.hour
    df["date"]        = df["timestamp"].dt.date
    df["status_class"] = (df["status"] // 100).astype(str) + "xx"
    df["is_error"]    = df["status"] >= 400

    print(f"[Parser] Parsed {len(df)} valid entries, {malformed} malformed lines skipped.")
    return df


def get_summary(df: pd.DataFrame) -> dict:
    """Return high-level statistics from parsed DataFrame."""
    return {
        "total_requests":  int(len(df)),
        "unique_ips":      int(df["ip"].nunique()),
        "unique_urls":     int(df["url"].nunique()),
        "start_time":      str(df["timestamp"].min()),
        "end_time":        str(df["timestamp"].max()),
        "error_count":     int(df["is_error"].sum()),
        "error_rate_pct":  round(df["is_error"].mean() * 100, 2),
        "status_dist":     df["status"].value_counts().to_dict(),
        "method_dist":     df["method"].value_counts().to_dict(),
        "top_ips":         df["ip"].value_counts().head(10).to_dict(),
        "top_urls":        df["url"].value_counts().head(10).to_dict(),
        "hourly_traffic":  df.groupby("hour").size().to_dict(),
        "bytes_total":     int(df["bytes"].sum()),
    }
