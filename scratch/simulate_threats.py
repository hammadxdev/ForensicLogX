import urllib.request
import json
import time

URL = "http://127.0.0.1:5000/api/logs/ingest"

threats = [
    {
        "name": "SQL Injection (Sigma Rule Match)",
        "raw_log": '192.168.1.100 - - [03/Jun/2026:10:01:00 +0500] "GET /dvwa/vuln.php?id=1%20UNION%20SELECT%20version() HTTP/1.1" 200 1204 "-" "Mozilla/5.0"',
        "log_type": "vulnlab_access",
        "source": "DVWA"
    },
    {
        "name": "JNDI / Log4Shell Exploit Pattern (Sigma Rule Match)",
        "raw_log": '192.168.1.99 - - [03/Jun/2026:10:00:00 +0500] "GET /dvwa/?id=/Basic/Command/Base64/ HTTP/1.1" 200 4502 "-" "Mozilla/5.0"',
        "log_type": "vulnlab_access",
        "source": "DVWA"
    },
    {
        "name": "ModSecurity CRS SQLi Deny Alert (ModSecurity Match)",
        "raw_log": '[Wed Jun 03 10:30:00.000000 2026] [:error] [pid 1234] [client 192.168.0.22:54321] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `DetectSQLi\' with parameter `` against variable `ARGS:id\' (Value: `1\' OR \'1\'=\'1\' ") [file "/etc/modsecurity/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "65"] [id "942100"] [rev ""] [msg "SQL Injection Detected"]',
        "log_type": "vulnlab_error",
        "source": "ModSecurity"
    }
]

print("="*70)
print("  ForensicLogX — Local Threat Ingestion Simulator")
print("  Target Server URL: " + URL)
print("="*70 + "\n")

for i, threat in enumerate(threats, start=1):
    print(f"[{i}] Simulating: {threat['name']}...")
    payload = {
        "raw_log": threat["raw_log"],
        "log_type": threat["log_type"],
        "source": threat["source"]
    }
    try:
        req = urllib.request.Request(
            URL,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as r:
            resp = json.loads(r.read().decode())
            print(f"    -> Response: {resp}")
        time.sleep(1.5)
    except Exception as e:
        print(f"    -> Failed to send: {e}")

print("\n" + "="*70)
print("  Simulation complete! Open the dashboard to view changes in:")
print("  - Live Threat Feed / Live Sigma Rules Engine Panels")
print("  - Incident Console & SIEM Log Viewer")
print("  - Attack Timeline / Real-Time Map Overlay")
print("="*70)
