"""
ForensicLogX — Threat Detection Regex Library
Pre-compiled regular expression patterns for parsing and identifying threat signatures.
Compiled at module load time for optimal performance.
"""

import re

# Base dictionary of raw regex patterns for web log analysis
RAW_PATTERNS = {
    "sql_injection": r"(?i)(union\s+all\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|update\s+.*\s+set|delete\s+from|information_schema|or\s+1\s*=\s*1|'\s*or\s*'\d+\d*'\s*=\s*'\d+\d*|admin'\s*--|admin'\s*#)",
    "blind_sql_injection": r"(?i)(sleep\(\s*\d+\s*\)|benchmark\(\s*\d+\s*,\s*.*\s*\)|waitfor\s+delay\s+'|dbms_pipe\.receive_message|pg_sleep\(\d+\)|coalesce\(|cast\(|declare\s+@)",
    "command_injection": r"(?i)(;|\||&&|`|\$\(.*?\))\s*(cat|wget|curl|sh|bash|id|whoami|ping|nc|netcat|uname|chmod|chown|python|perl|eval|exec)\b",
    "xss_reflected": r"(?i)(<script.*?>|javascript:|onerror\s*=|onload\s*=|alert\(|confirm\(|prompt\(|document\.cookie|window\.location|eval\(|String\.fromCharCode|svg/onload)",
    "xss_stored": r"(?i)(<script.*?>.*?<\/script>|<iframe.*?>|src\s*=\s*['\"]javascript:|onmouseover\s*=)",
    "xss_dom": r"(?i)(location\.(hash|search|href)|document\.(write|writeln)|innerHTML|eval\(.*?\bhash\b)",
    "lfi": r"(?i)(\betc/passwd\b|\betc/shadow\b|\betc/group\b|\betc/hosts\b|\bproc/self/|\bboot\.ini\b|win\.ini|system\.ini)",
    "rfi": r"(?i)(\b(http|https|ftp|php|data|file)://[^\s]+?\.(php|txt|html|jsp|asp|sh))",
    "directory_traversal": r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)",
    "webshell_upload": r"(?i)\.(php[3457]?|phtml|asp|aspx|jsp|jspx|exe|sh|pl|py|cgi)$",
    "webshell_execution": r"(?i)(cmd|shell|c99|r57|wso|weevely|b374k)\.php\?(cmd|exec|run|pass|act|code)=",
    "open_redirect": r"(?i)([\?&](url|next|redirect|goto|dest|destination|forward|target)=https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})",
    "forced_browsing": r"(?i)\.(bak|sql|db|zip|tar|gz|rar|7z|env|git|conf|config|log|backup|ini|yaml|yml|json)$",
    "admin_panel_recon": r"(?i)^/(wp-admin|phpmyadmin|admin|cpanel|administrator|manager/html|webmin|controlpanel|directadmin|login_admin|backend|dashboard/admin)\b",
    "user_enumeration": r"(?i)/(users?|members?|accounts?|profiles?)/(\d+|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
    "api_abuse": r"^/api/(v1|v2|v3)?/(auth|users|payments|orders|transfers|admin)\b",
    "sensitive_data_exposure": r"(?i)(---BEGIN\s+RSA\s+PRIVATE|4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|[a-zA-Z0-9_\-\.]{20,}\.amazonaws\.com|AIza[0-9A-Za-z\-_{}]{35})",
    "auth_bypass": r"(?i)/(bypass|auth-bypass|no-auth|guest-login|skip-auth)\b",
    "privilege_escalation": r"(?i)([\?&](role|admin|privilege|user_type|access_level)=admin(istrator)?|[\?&]is_admin=(true|1))",
    "js_injection": r"(?i)(<script|javascript:|eval\s*\(|setTimeout\s*\(|setInterval\s*\()",
    "csp_bypass": r"(?i)(data:text/html|unsafe-inline|unsafe-eval|script-src\s+'self'\s+[^;]*)",
    "session_weak_ids": r"(?i)(sessionid|sessid|phpsessid|jsessionid|token)=([0-9]{1,8}|[a-f0-9]{8})$",
    "bot_crawler": r"(?i)(nikto|sqlmap|acunetix|dirbuster|wfuzz|gobuster|nmap|masscan|nuclei|hydra|zgrab|censys|shodan|python-requests|scrapy|headless|curl|wget|libwww-perl|lwp-trivial|pycurl|urllib|httpie|postmanruntime|go-http-client|rust-http-client|burpsuite|zaproxy|scanner|bot|crawler|spider)"
}

# Compiled regex dictionary
REGEX_LIBRARY = {}

def compile_patterns():
    global REGEX_LIBRARY
    for key, pattern in RAW_PATTERNS.items():
        REGEX_LIBRARY[key] = re.compile(pattern)

# Compile upon import
compile_patterns()
