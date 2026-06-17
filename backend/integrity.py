"""
ForensicLogX — Log Integrity & Chain of Custody Module
Implements SHA-256 hashing for tamper detection and
forensic chain of custody tracking.
"""

import hashlib
import json
import os
from datetime import datetime


# ─── SHA-256 Hashing ─────────────────────────────────────────────────────────

def compute_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file. Reads in chunks for large files."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def save_hash(filepath: str, file_hash: str, hash_folder: str) -> str:
    """
    Save a hash record to disk for future verification.
    Returns the path of the saved hash file.
    """
    os.makedirs(hash_folder, exist_ok=True)
    filename = os.path.basename(filepath)
    record = {
        "filename":   filename,
        "filepath":   filepath,
        "sha256":     file_hash,
        "file_size":  os.path.getsize(filepath),
        "collected":  datetime.now().isoformat(),
        "algorithm":  "SHA-256",
    }
    hash_path = os.path.join(hash_folder, filename + ".hash.json")
    with open(hash_path, "w") as f:
        json.dump(record, f, indent=2)
    return hash_path


def verify_integrity(filepath: str, hash_folder: str) -> dict:
    """
    Re-hash a file and compare against stored baseline.
    Returns verification result dict.
    """
    filename  = os.path.basename(filepath)
    hash_path = os.path.join(hash_folder, filename + ".hash.json")

    if not os.path.exists(hash_path):
        return {"status": "no_baseline", "message": "No stored hash found for this file."}

    with open(hash_path) as f:
        record = json.load(f)

    current_hash = compute_sha256(filepath)
    match = current_hash == record["sha256"]

    return {
        "status":        "match" if match else "mismatch",
        "match":         match,
        "original_hash": record["sha256"],
        "current_hash":  current_hash,
        "collected":     record["collected"],
        "file_size":     record["file_size"],
        "message":       "Integrity verified — file unchanged." if match else "TAMPER DETECTED — hash mismatch!",
    }


# ─── Chain of Custody ────────────────────────────────────────────────────────

class ChainOfCustody:
    """
    Records every action performed on evidence (log file)
    in chronological order — mimics forensic standards.
    """

    def __init__(self, analyst: str, filename: str, file_hash: str):
        self.analyst  = analyst
        self.filename = filename
        self.entries  = []
        self.add_entry("Evidence Collected", f"File '{filename}' collected for analysis", "System")
        self.add_entry("Hash Computed", f"SHA-256: {file_hash}", "System")

    def add_entry(self, action: str, detail: str, actor: str = None) -> None:
        self.entries.append({
            "timestamp": datetime.now().isoformat(),
            "action":    action,
            "detail":    detail,
            "actor":     actor or self.analyst,
        })

    def to_dict(self) -> dict:
        return {
            "case_id":   f"FLX-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "analyst":   self.analyst,
            "filename":  self.filename,
            "created":   datetime.now().isoformat(),
            "entries":   self.entries,
        }

    def export_json(self, output_dir: str) -> str:
        """Save chain of custody as JSON file."""
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, f"custody_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        return path
