import requests
import os

# Create a session to keep cookies
session = requests.Session()

# Create a dummy log file in Apache Combined Log Format
dummy_log_content = """127.0.0.1 - - [03/Jun/2026:23:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 4500 "-" "Mozilla/5.0"
127.0.0.1 - - [03/Jun/2026:23:01:00 +0000] "GET /admin HTTP/1.1" 401 230 "-" "Mozilla/5.0"
1.2.3.4 - - [03/Jun/2026:23:02:00 +0000] "GET /etc/passwd HTTP/1.1" 404 120 "-" "Mozilla/5.0"
"""
with open("scratch/test_log.txt", "w") as f:
    f.write(dummy_log_content)

print("1. Uploading dummy log file...")
files = {
    'file': ('test_log.txt', open('scratch/test_log.txt', 'rb'), 'text/plain')
}
data = {
    'analyst': 'Gohar Ali'
}
res1 = session.post("http://127.0.0.1:5000/api/upload", files=files, data=data)
print("Upload status:", res1.status_code)
if res1.status_code != 200:
    print("Upload failed:", res1.text)
    exit(1)

print("Upload response keys:", res1.json().keys())
print("Session Cookies:", session.cookies.get_dict())

# 2. Trigger the PDF report generation/download
print("\n2. Downloading PDF report...")
payload = {
    "analyst": "Gohar Ali",
    "organization": "BS Digital Forensics & Cyber Security"
}
res2 = session.post("http://127.0.0.1:5000/api/report/generate", json=payload)
print("Status Code:", res2.status_code)
print("Headers:", dict(res2.headers))
print("Response length:", len(res2.content))

if len(res2.content) > 100:
    print("PDF header:", res2.content[:20])
    with open("scratch/downloaded_report.pdf", "wb") as f:
        f.write(res2.content)
    print("Saved downloaded report size:", os.path.getsize("scratch/downloaded_report.pdf"))
else:
    print("Content preview:", res2.text)
