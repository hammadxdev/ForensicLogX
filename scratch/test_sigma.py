import sys
import os
import time
import json
import sqlite3
import subprocess
import urllib.request

PORT = 5558
SERVER_URL = f"http://127.0.0.1:{PORT}"
DB_PATH = r"e:\ForensicLogX\dataset\crs_rules.db"

# Start server as subprocess
print("[TEST] Starting test server process on port 5558...")
server_proc = subprocess.Popen(
    [sys.executable, r"scratch/run_test_server.py"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

# Wait for server to boot in a retry loop (up to 15 seconds)
server_ready = False
print("[TEST] Waiting for server to boot and load Sigma Rules...")
for attempt in range(15):
    time.sleep(1.0)
    # Check if process exited
    if server_proc.poll() is not None:
        print("[FAIL] Server process exited early!")
        out, _ = server_proc.communicate()
        print(f"Server Output:\n{out}")
        sys.exit(1)
        
    try:
        req = urllib.request.Request(f"{SERVER_URL}/api/sigma/rules/list")
        with urllib.request.urlopen(req) as r:
            rules = json.loads(r.read().decode())
            print(f"[TEST] Connection established. Rules count: {len(rules)}")
            server_ready = True
            break
    except urllib.error.URLError:
        print(f"  - Attempt {attempt + 1}: Server not ready yet...")
        continue

if not server_ready:
    print("[FAIL] Server failed to start within 15 seconds!")
    server_proc.kill()
    sys.exit(1)

try:
    # 2. Test Rules List API (assertion)
    assert len(rules) > 0, "No Sigma rules loaded!"
    titles = [r["title"] for r in rules]
    assert any("JNDI" in t or "SQL" in t for t in titles), "Expected JNDI or SQLi rule in repository!"

    # 3. Test Ingesting Log that matches JNDI exploit (web_jndi_exploit.yml keywords)
    print("[TEST] Sending log matching JNDI Exploit rule...")
    jndi_log = '192.168.1.99 - - [03/Jun/2026:10:00:00 +0500] "GET /dvwa/?id=/Basic/Command/Base64/ HTTP/1.1" 200 4502 "-" "Mozilla/5.0"'
    payload = {
        "raw_log": jndi_log,
        "log_type": "vulnlab_access",
        "source": "DVWA"
    }
    
    req = urllib.request.Request(
        f"{SERVER_URL}/api/logs/ingest",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as r:
        resp = json.loads(r.read().decode())
        print(f"[TEST] Ingest Response: {resp}")
        assert resp["status"] == "success", "Log ingest failed!"

    # 4. Test Ingesting Log that matches SQL Injection (web_sql_injection_in_access_logs.yml)
    print("[TEST] Sending log matching SQL Injection rule...")
    sqli_log = '192.168.1.100 - - [03/Jun/2026:10:01:00 +0500] "GET /dvwa/vuln.php?id=1%20UNION%20SELECT%20version() HTTP/1.1" 200 1204 "-" "Mozilla/5.0"'
    payload_sqli = {
        "raw_log": sqli_log,
        "log_type": "vulnlab_access",
        "source": "DVWA"
    }
    
    req = urllib.request.Request(
        f"{SERVER_URL}/api/logs/ingest",
        data=json.dumps(payload_sqli).encode(),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as r:
        resp = json.loads(r.read().decode())
        print(f"[TEST] Ingest Response (SQLi): {resp}")
        assert resp["status"] == "success", "SQLi Log ingest failed!"

    # 5. Query and verify Sigma Stats API
    print("[TEST] Querying /api/sigma/stats...")
    req = urllib.request.Request(f"{SERVER_URL}/api/sigma/stats")
    with urllib.request.urlopen(req) as r:
        stats = json.loads(r.read().decode())
        print(f"[TEST] Sigma Stats: {json.dumps(stats, indent=2)}")
        
        # Verify stats counters incremented
        assert stats["total"] >= 2, f"Expected at least 2 alert triggers, got {stats['total']}"
        assert stats["by_level"]["high"] >= 2, "Expected high level alerts"
        assert stats["by_category"]["webserver"] >= 2, "Expected webserver category alerts"

    # 6. Verify alerts are stored in detected_attacks table
    print("[TEST] Checking SQLite DB for stored Sigma alerts...")
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM detected_attacks WHERE attack_type LIKE 'Sigma Alert%'").fetchall()
        print(f"[TEST] Stored Sigma alerts in DB: {len(rows)}")
        assert len(rows) >= 2, f"Expected at least 2 database entries, got {len(rows)}"
        for row in rows:
            print(f"  - DB Alert: {row['description']} | Source: {row['source_ip']} | Attack: {row['attack_type']}")

except Exception as e:
    print(f"\n[FAIL] Test encountered an error: {e}")
    server_proc.kill()
    sys.exit(1)

# Clean shutdown of server
print("[TEST] Shutting down test server...")
server_proc.kill()
print("\n[SUCCESS] E2E Sigma Rules Engine Integration Test Succeeded!")
sys.exit(0)
