"""
ForensicLogX — IOC (Indicators of Compromise) Library
Contains collections of known malicious User-Agents, scanner signatures, 
suspicious file names, and threshold configurations.
"""

# Collection of over 200 suspicious or automation-oriented User-Agent substrings
SUSPICIOUS_USER_AGENTS = [
    "nikto", "sqlmap", "acunetix", "dirbuster", "wfuzz", "gobuster", "nmap", 
    "masscan", "nuclei", "hydra", "zgrab", "amap", "arachni", "brutus", "cain",
    "caldera", "commix", "crackmapexec", "dirb", "dirbuster", "dnsenum", "dnsrecon",
    "fierce", "fimap", "golismero", "hashcat", "havij", "john", "medusa", "metasploit",
    "nessus", "netsparker", "nstalker", "owasp-zap", "pangolin", "qualys", "recon-ng",
    "skipfish", "sqlmap", "sqlninja", "superscan", "w3af", "webinspect", "whatweb",
    "wpscan", "xsser", "zenmap", "censys", "shodan", "zoomeye", "python-requests",
    "scrapy", "headless", "phantomjs", "puppeteer", "playwright", "curl", "wget", 
    "libwww-perl", "lwp-trivial", "pycurl", "urllib", "httpie", "postmanruntime",
    "go-http-client", "rust-http-client", "perl", "ruby", "java/", "okhttp",
    "axis2", "paros", "wget/", "curl/", "aria2", "download-manager", "httrack",
    "offline-explorer", "webcopier", "teleport", "webstripper", "wget-active",
    "nikto-dev", "sqlmap/", "hydra/", "dirbuster/", "gobuster/", "nmap/", 
    "masscan/", "nuclei/", "wfuzz/", "dirb/", "nikto/", "zap/", "acunetix/",
    "whatweb/", "wpscan/", "commix/", "amap/", "censysscan", "shodan-recon",
    "shodansystem", "zoomeyespider", "binaryedge", "shadowserver", "leakix",
    "internet-measurement", "stretchoid", "scans.io", "openvas", "greenbone",
    "nessus-agent", "qualys-agent", "rapid7", "insightvm", "nexpose", "tripwire",
    "fortify", "appscan", "burpsuite", "burpcollaborator", "owasp", "dircheck",
    "webscanner", "vulnerability", "exploit", "scanner", "security-scan",
    "pentest", "hacker", "attack", "cyber", "malicious", "botnet", "crawler",
    "spider", "agent", "automated", "fetcher", "scraper", "grabber", "downloader",
    "leech", "mirror", "offline", "site-grabber", "teleport-pro", "webzip",
    "wtrack", "weblogs", "log-analysis", "scan-bot", "security-audit", 
    "audit-bot", "test-agent", "fuzzing", "fuzzer", "fuzz", "brute", "bruteforce",
    "spray", "spraying", "credential-stuffing", "stuffing", "cracking",
    "password-cracker", "login-brute", "admin-fuzzer", "dir-buster", "file-buster",
    "path-buster", "vulnerability-scanner", "port-scanner", "network-scanner",
    "web-scanner", "database-scanner", "sql-scanner", "xss-scanner", "lfi-scanner",
    "rfi-scanner", "rce-scanner", "command-scanner", "injection-scanner",
    "api-scanner", "token-scanner", "key-scanner", "cookie-scanner", "header-scanner",
    "user-agent-scanner", "parameter-scanner", "query-scanner", "form-scanner",
    "file-uploader", "webshell-uploader", "malware-uploader", "trojan-uploader",
    "backdoor-uploader", "exploit-uploader", "payload-uploader", "script-uploader",
    "shell-uploader", "command-uploader", "runner", "executor", "invoker", "caller"
]

# Known malicious path fragments (files, extensions, parameters)
MALICIOUS_PATH_FRAGMENTS = [
    # Webshells & backdoors
    "shell.php", "cmd.php", "c99.php", "r57.php", "wso.php", "weevely.php", 
    "b374k.php", "cmd.aspx", "shell.aspx", "cmd.jsp", "shell.jsp", "cmd.asp", 
    "shell.asp", "index.php?cmd=", "conn.php", "db.php?code=",
    # Configuration / Environment files
    ".env", "web.config", "wp-config.php", "config.php.bak", "settings.py", 
    "database.yml", ".git/config", ".git/HEAD", ".svn/entries", ".htaccess",
    # Sensitive utilities & backups
    "phpinfo.php", "info.php", "test.php", "setup.php", "install.php", 
    "upgrade.php", "admin.php.bak", "db.sql", "backup.sql", "dump.sql", 
    "database.sql", "mysql.sql", "backup.zip", "site.zip", "www.zip",
    # Linux Sensitive paths
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts", "/proc/self",
    "/proc/version", "/proc/cmdline", "/etc/issue", "/etc/hostname",
    # Windows Sensitive paths
    "win.ini", "boot.ini", "windows/win.ini", "windows/system.ini",
    # Dynamic language descriptors
    "eval(", "exec(", "system(", "passthru(", "shell_exec(", "popen(", "proc_open("
]

# Admin panels & endpoints targeted by scanning scripts
ADMIN_ENDPOINTS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/cpanel", "/administrator", 
    "/manager/html", "/webmin", "/controlpanel", "/directadmin", "/login_admin",
    "/backend", "/dashboard/admin", "/admin/login", "/admin_login", "/wp-login.php"
]

# Pre-defined rate-limit and threshold configurations
THRESHOLD_CONFIGS = {
    "brute_force": {
        "count": 10,
        "window_seconds": 300,  # 5 minutes
        "status_codes": [401, 403]
    },
    "credential_stuffing": {
        "unique_users": 5,
        "window_seconds": 300,
        "status_codes": [401, 403]
    },
    "password_spraying": {
        "unique_ips": 10,
        "window_seconds": 300,
        "status_codes": [401, 403]
    },
    "ddos": {
        "requests_per_minute": 100,
        "window_seconds": 60
    },
    "api_abuse": {
        "requests_per_minute": 50,
        "window_seconds": 60
    },
    "dir_enumeration": {
        "404_count": 20,
        "window_seconds": 60
    }
}
