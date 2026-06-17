import sys

sys.stdout.reconfigure(encoding='utf-8')

with open("e:/ForensicLogX/frontend/static/js/app.js", "r", encoding="utf-8") as f:
    lines = f.readlines()

for idx, line in enumerate(lines):
    if "style" in line:
        print(f"Line {idx+1}: {line.strip()}")
