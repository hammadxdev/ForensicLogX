"""
ForensicLogX — Enterprise-Grade Detection Rules Library
Contains rule metadata, descriptions, MITRE ATT&CK mappings, OWASP references,
and remediation recommendations.
"""

DETECTION_RULES = {
    # ─── Authentication Attacks ───────────────────────────────────────────────
    "FLX-001": {
        "id": "FLX-001",
        "name": "HTTP Brute Force Attack",
        "category": "Authentication",
        "attack_type": "Brute Force",
        "severity": "HIGH",
        "confidence": 80,
        "description": "Repeated authentication failures (401/403) from a single IP address targeting authentication endpoints.",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Brute Force",
            "technique_id": "T1110"
        },
        "owasp": "A07:2021-Identification and Authentication Failures",
        "recommendation": {
            "block_ip": True,
            "rate_limit": True,
            "waf_rule": "SecRule IP:PREV_AUTH_FAILURES \"@ge 10\" \"id:100001,deny,status:403,msg:'IP blocked due to brute force'\"",
            "remediation": "Implement account lockout policies, multi-factor authentication (MFA), and rate-limiting on login endpoints."
        }
    },
    "FLX-002": {
        "id": "FLX-002",
        "name": "Credential Stuffing Attempt",
        "category": "Authentication",
        "attack_type": "Credential Stuffing",
        "severity": "CRITICAL",
        "confidence": 85,
        "description": "Large volume of login attempts using multiple usernames from a single source IP, indicating potential credential stuffing.",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Brute Force: Credential Stuffing",
            "technique_id": "T1110.004"
        },
        "owasp": "A07:2021-Identification and Authentication Failures",
        "recommendation": {
            "block_ip": True,
            "rate_limit": True,
            "waf_rule": "SecRule ARGS:password \"@regex ...\" \"id:100002,deny,status:429\"",
            "remediation": "Deploy CAPTCHA on login screens, check passwords against breached databases, and analyze login velocity."
        }
    },
    "FLX-003": {
        "id": "FLX-003",
        "name": "Password Spraying Attack",
        "category": "Authentication",
        "attack_type": "Password Spraying",
        "severity": "HIGH",
        "confidence": 75,
        "description": "Single password tried against a large number of usernames from one or more IP addresses over a short time window.",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Brute Force: Password Spraying",
            "technique_id": "T1110.003"
        },
        "owasp": "A07:2021-Identification and Authentication Failures",
        "recommendation": {
            "block_ip": True,
            "rate_limit": True,
            "waf_rule": "SecRule IP:SPRAY_COUNT \"@ge 20\" \"id:100003,deny,status:403\"",
            "remediation": "Enforce strong unique passwords, monitor logins for atypical IP locations, and restrict general endpoint access."
        }
    },

    # ─── Injection Attacks ──────────────────────────────────────────────────
    "FLX-004": {
        "id": "FLX-004",
        "name": "SQL Injection (Classic)",
        "category": "Injection",
        "attack_type": "SQL Injection",
        "severity": "CRITICAL",
        "confidence": 90,
        "description": "Classic SQL Injection queries (UNION SELECT, OR 1=1) detected in request arguments or URLs.",
        "mitre": {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190"
        },
        "owasp": "A03:2021-Injection",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule ARGS \"@rx (union\\s+select|select\\s+.*\\s+from|drop\\s+table)\" \"id:100004,deny,status:403,msg:'SQL Injection Attempt'\"",
            "remediation": "Use prepared statements (parameterized queries), object-relational mapping (ORM) frameworks, and input validation allowlists."
        }
    },
    "FLX-005": {
        "id": "FLX-005",
        "name": "Blind SQL Injection Attempt",
        "category": "Injection",
        "attack_type": "Blind SQL Injection",
        "severity": "CRITICAL",
        "confidence": 85,
        "description": "Time-based or boolean-based blind SQL injection patterns (e.g., SLEEP, BENCHMARK, conditional clauses) in query strings.",
        "mitre": {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190"
        },
        "owasp": "A03:2021-Injection",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule ARGS \"@rx (sleep\\(|benchmark\\(|waitfor\\s+delay)\" \"id:100005,deny,status:403\"",
            "remediation": "Disable detailed database error messages, enforce strict type checks, and restrict database privileges."
        }
    },
    "FLX-006": {
        "id": "FLX-006",
        "name": "OS Command Injection",
        "category": "Injection",
        "attack_type": "Command Injection",
        "severity": "CRITICAL",
        "confidence": 95,
        "description": "Shell commands or command separator sequences (;, &&, |, `) targeting execution of Linux utilities (cat, wget, curl, sh) in parameters.",
        "mitre": {
            "tactic": "Execution",
            "tactic_id": "TA0002",
            "technique": "Command and Scripting Interpreter",
            "technique_id": "T1059"
        },
        "owasp": "A03:2021-Injection",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule ARGS \"@rx (;|\\||\\&\\&|\\`)\\s*(cat|wget|curl|sh|bash|id|whoami|ping)\" \"id:100006,deny,status:403\"",
            "remediation": "Avoid passing user input directly to system shells. Use system APIs (e.g., subprocess with list args) instead of string concatenation."
        }
    },
    "FLX-007": {
        "id": "FLX-007",
        "name": "Cross-Site Scripting (Reflected)",
        "category": "Injection",
        "attack_type": "XSS Reflected",
        "severity": "HIGH",
        "confidence": 90,
        "description": "Javascript execution payload (e.g., <script>, onerror, onload) sent inside request parameters, expecting to be reflected.",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Steal Web Session Cookie",
            "technique_id": "T1539"
        },
        "owasp": "A03:2021-Injection",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule ARGS \"@rx (<script|javascript:|onerror=|onload=)\" \"id:100007,deny,status:403\"",
            "remediation": "Context-aware output encoding (HTML, Javascript, Attribute context encoding) and strict Content Security Policy (CSP)."
        }
    },
    "FLX-008": {
        "id": "FLX-008",
        "name": "Cross-Site Scripting (Stored)",
        "category": "Injection",
        "attack_type": "XSS Stored",
        "severity": "HIGH",
        "confidence": 80,
        "description": "Persistence of script payloads on endpoints like post forms, message uploads, or comment boxes.",
        "mitre": {
            "tactic": "Lateral Movement",
            "tactic_id": "TA0008",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190"
        },
        "owasp": "A03:2021-Injection",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule ARGS \"@rx (<script.*>|src=.*javascript:)\" \"id:100008,deny,status:403\"",
            "remediation": "Sanitize inputs on the backend using HTML sanitization libraries (e.g., DOMPurify or Bleach) before storing in the database."
        }
    },
    "FLX-009": {
        "id": "FLX-009",
        "name": "Cross-Site Scripting (DOM)",
        "category": "Injection",
        "attack_type": "XSS DOM",
        "severity": "HIGH",
        "confidence": 70,
        "description": "Targeting client-side Javascript code sinks (location.hash, document.write) via URL parameters and fragments.",
        "mitre": {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Drive-by Compromise",
            "technique_id": "T1189"
        },
        "owasp": "A03:2021-Injection",
        "recommendation": {
            "block_ip": False,
            "rate_limit": False,
            "waf_rule": "SecRule REQUEST_URI \"@rx (#.*(javascript:|eval\\(|document\\.write))\" \"id:100009,pass\"",
            "remediation": "Avoid using document.write, element.innerHTML, or eval with untrusted inputs. Use element.textContent or element.setAttribute instead."
        }
    },

    # ─── File-Based Attacks ──────────────────────────────────────────────────
    "FLX-010": {
        "id": "FLX-010",
        "name": "Local File Inclusion",
        "category": "File-Based",
        "attack_type": "Local File Inclusion (LFI)",
        "severity": "HIGH",
        "confidence": 90,
        "description": "Path patterns pointing to sensitive local system configuration files (e.g., /etc/passwd, /etc/hosts) in URL parameters.",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Unsecured File Sharing",
            "technique_id": "T1083"
        },
        "owasp": "A01:2021-Broken Access Control",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule ARGS \"@rx (/etc/passwd|/etc/shadow|/etc/group|/proc/self/)\" \"id:100010,deny,status:403\"",
            "remediation": "Avoid dynamic file inclusion. Use static lists/indexes to select files, or enforce strict file path normalization and allowlists."
        }
    },
    "FLX-011": {
        "id": "FLX-011",
        "name": "Remote File Inclusion",
        "category": "File-Based",
        "attack_type": "Remote File Inclusion (RFI)",
        "severity": "CRITICAL",
        "confidence": 95,
        "description": "Inclusion of absolute external URLs (http://, https://, ftp://) inside path parameters, forcing server execution of remote scripts.",
        "mitre": {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190"
        },
        "owasp": "A01:2021-Broken Access Control",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule ARGS \"@rx (https?|ftp|php)://\" \"id:100011,deny,status:403\"",
            "remediation": "Disable allow_url_include and allow_url_fopen in PHP configurations, or configure firewall policies to restrict server egress calls."
        }
    },
    "FLX-012": {
        "id": "FLX-012",
        "name": "Directory Traversal",
        "category": "File-Based",
        "attack_type": "Directory Traversal",
        "severity": "HIGH",
        "confidence": 90,
        "description": "Attempts to escape the web root using parent directory referencing operators (../ or ..\\).",
        "mitre": {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "File and Directory Discovery",
            "technique_id": "T1083"
        },
        "owasp": "A01:2021-Broken Access Control",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule REQUEST_URI \"@rx \\.\\./\" \"id:100012,deny,status:403\"",
            "remediation": "Sanitize and normalize paths before resolving them. Ensure paths remain strictly within the intended base directory using safe path APIs."
        }
    },
    "FLX-013": {
        "id": "FLX-013",
        "name": "Malicious File Upload Attempt",
        "category": "File-Based",
        "attack_type": "Malicious File Upload",
        "severity": "HIGH",
        "confidence": 85,
        "description": "Attempts to upload executable formats or script formats (.php, .phtml, .asp, .jsp, .exe, .sh) to upload endpoints.",
        "mitre": {
            "tactic": "Resource Development",
            "tactic_id": "TA0042",
            "technique": "Upload Malware",
            "technique_id": "T1587"
        },
        "owasp": "A04:2021-Insecure Design",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule FILES \"@rx \\.(php[345]?|phtml|asp|jsp|exe|sh|pl|py)$\" \"id:100013,deny,status:403\"",
            "remediation": "Validate files using mime-types and magic numbers, rename uploaded files dynamically, and store them outside the public web root."
        }
    },
    "FLX-014": {
        "id": "FLX-014",
        "name": "Web Shell Upload & Execution",
        "category": "File-Based",
        "attack_type": "Web Shell Upload",
        "severity": "CRITICAL",
        "confidence": 95,
        "description": "Access or code execution command requests targeting uploaded script files (e.g., cmd.php?cmd=..., shell.php, c99.php).",
        "mitre": {
            "tactic": "Persistence",
            "tactic_id": "TA0003",
            "technique": "Server Software Component: Web Shell",
            "technique_id": "T1505.003"
        },
        "owasp": "A03:2021-Injection",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule REQUEST_FILENAME \"@rx (shell|cmd|c99|r57|wso|weevely|b374k)\\.php\" \"id:100014,deny,status:403\"",
            "remediation": "Disable execute permissions on upload directories (e.g., `Options -ExecCGI` or `php_flag engine off` in Apache config)."
        }
    },

    # ─── Session & Access Control Attacks ─────────────────────────────────────
    "FLX-015": {
        "id": "FLX-015",
        "name": "CSRF Indicator",
        "category": "Session & Access Control",
        "attack_type": "CSRF Indicators",
        "severity": "MEDIUM",
        "confidence": 60,
        "description": "Sensitive state-changing requests (POST/PUT/DELETE) missing standard anti-CSRF headers, referencing anomalous referer domains.",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Credentials from Web Browsers",
            "technique_id": "T1555.003"
        },
        "owasp": "A01:2021-Broken Access Control",
        "recommendation": {
            "block_ip": False,
            "rate_limit": False,
            "waf_rule": "SecRule REQUEST_METHOD \"@strEq POST\" \"id:100015,pass\"",
            "remediation": "Enforce CSRF protection tokens for all mutable state actions, or configure cookies with `SameSite=Strict` or `SameSite=Lax` flags."
        }
    },
    "FLX-016": {
        "id": "FLX-016",
        "name": "Open Redirect Abuse",
        "category": "Session & Access Control",
        "attack_type": "Open Redirect",
        "severity": "MEDIUM",
        "confidence": 80,
        "description": "Redirect arguments (url, next, redirect, goto) containing external domains (e.g., //evil.com or http://evil.com) in request URLs.",
        "mitre": {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Phishing: Spearphishing Link",
            "technique_id": "T1566.002"
        },
        "owasp": "A01:2021-Broken Access Control",
        "recommendation": {
            "block_ip": False,
            "rate_limit": False,
            "waf_rule": "SecRule ARGS:redirect \"@rx ^https?://\" \"id:100016,deny,status:403\"",
            "remediation": "Use relative path redirection, validate absolute redirect domains against a strict allowlist, or display a warning before exit."
        }
    },
    "FLX-017": {
        "id": "FLX-017",
        "name": "Forced Browsing / Sensitive File Probe",
        "category": "Session & Access Control",
        "attack_type": "Forced Browsing",
        "severity": "MEDIUM",
        "confidence": 75,
        "description": "Attempts to access sensitive backup files (.bak, .sql, .zip, .tar.gz) or hidden config folders directly.",
        "mitre": {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "File and Directory Discovery",
            "technique_id": "T1083"
        },
        "owasp": "A01:2021-Broken Access Control",
        "recommendation": {
            "block_ip": True,
            "rate_limit": True,
            "waf_rule": "SecRule REQUEST_FILENAME \"@rx \\.(bak|sql|zip|gz|env|conf|git|log)$\" \"id:100017,deny,status:403\"",
            "remediation": "Configure web servers to deny direct downloads of configuration, log, backup, and environment files."
        }
    },
    "FLX-018": {
        "id": "FLX-018",
        "name": "Administrative Panel Discovery",
        "category": "Session & Access Control",
        "attack_type": "Admin Panel Recon",
        "severity": "MEDIUM",
        "confidence": 70,
        "description": "Probing for administrative paths (e.g., /admin, /wp-admin, /phpmyadmin, /cpanel) by unauthenticated user-agents.",
        "mitre": {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "File and Directory Discovery",
            "technique_id": "T1083"
        },
        "owasp": "A01:2021-Broken Access Control",
        "recommendation": {
            "block_ip": False,
            "rate_limit": True,
            "waf_rule": "SecRule REQUEST_FILENAME \"@rx ^/(wp-admin|phpmyadmin|admin/)\" \"id:100018,pass\"",
            "remediation": "Restrict administrative panels to authorized IP addresses, use different ports, or enforce multi-factor authentication."
        }
    },
    "FLX-019": {
        "id": "FLX-019",
        "name": "User/ID Enumeration Attempt",
        "category": "Session & Access Control",
        "attack_type": "User/ID Enumeration",
        "severity": "MEDIUM",
        "confidence": 65,
        "description": "Rapid sequential queries targeting user profiles or identifiers (e.g., /users/1, /users/2, etc.) showing resource scraping behavior.",
        "mitre": {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Account Discovery",
            "technique_id": "T1087"
        },
        "owasp": "A01:2021-Broken Access Control",
        "recommendation": {
            "block_ip": False,
            "rate_limit": True,
            "waf_rule": "SecRule REQUEST_URI \"@rx /users/\\d+\" \"id:100019,pass\"",
            "remediation": "Use UUIDs or non-sequential identifiers, implement rate limits on APIs, and return generic errors for account existence checks."
        }
    },
    "FLX-020": {
        "id": "FLX-020",
        "name": "API Abuse / Rate Limit Exhaustion",
        "category": "Session & Access Control",
        "attack_type": "API Abuse",
        "severity": "HIGH",
        "confidence": 80,
        "description": "High frequency requests targeting critical API endpoints, causing resource exhaustion or data scraping.",
        "mitre": {
            "tactic": "Exfiltration",
            "tactic_id": "TA0010",
            "technique": "Exfiltration Over Web Service",
            "technique_id": "T1567"
        },
        "owasp": "A05:2021-Security Misconfiguration",
        "recommendation": {
            "block_ip": True,
            "rate_limit": True,
            "waf_rule": "SecRule IP:API_RATE_LIMIT \"@ge 100\" \"id:100020,deny,status:429\"",
            "remediation": "Implement API gateway-level rate limiting, token buckets, and API key authentication."
        }
    },
    "FLX-021": {
        "id": "FLX-021",
        "name": "Directory Enumeration Probe",
        "category": "Session & Access Control",
        "attack_type": "Directory Enumeration",
        "severity": "HIGH",
        "confidence": 85,
        "description": "High rates of 404 response codes from a single IP, indicative of a directory buster or path scanning tool.",
        "mitre": {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "File and Directory Discovery",
            "technique_id": "T1083"
        },
        "owasp": "A01:2021-Broken Access Control",
        "recommendation": {
            "block_ip": True,
            "rate_limit": True,
            "waf_rule": "SecRule IP:404_STORM \"@ge 30\" \"id:100021,deny,status:403\"",
            "remediation": "Configure the server to respond with generic pages, block aggressive scanners, and enforce absolute thresholds on 404 counts."
        }
    },

    # ─── Infrastructure & Reconnaissance ──────────────────────────────────────
    "FLX-022": {
        "id": "FLX-022",
        "name": "Port Scanning Footprints",
        "category": "Reconnaissance",
        "attack_type": "Port Scan Indicators",
        "severity": "HIGH",
        "confidence": 75,
        "description": "Rapid requests hitting non-standard, administrative, or diagnostic ports from a single external IP.",
        "mitre": {
            "tactic": "Reconnaissance",
            "tactic_id": "TA0043",
            "technique": "Active Scanning",
            "technique_id": "T1595"
        },
        "owasp": "A05:2021-Security Misconfiguration",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule IP:PORTSCAN \"@ge 5\" \"id:100022,deny,status:403\"",
            "remediation": "Enable host-level firewalls (IPTables/UFW), configure port-knocking or VPN for administrative services, and disable unused services."
        }
    },
    "FLX-023": {
        "id": "FLX-023",
        "name": "Malicious Bot or Web Crawler",
        "category": "Reconnaissance",
        "attack_type": "Bot/Crawler",
        "severity": "LOW",
        "confidence": 85,
        "description": "Known aggressive scraping tools, vulnerability scanners, or automated bots detected via User-Agent patterns.",
        "mitre": {
            "tactic": "Discovery",
            "tactic_id": "TA0007",
            "technique": "Software Discovery",
            "technique_id": "T1518"
        },
        "owasp": "A05:2021-Security Misconfiguration",
        "recommendation": {
            "block_ip": False,
            "rate_limit": True,
            "waf_rule": "SecRule REQUEST_HEADERS:User-Agent \"@rx (wget|curl|python-requests|scrapy|headless|nikto|sqlmap|nmap)\" \"id:100023,deny,status:403\"",
            "remediation": "Configure `robots.txt` guidelines, block requests that contain signature automated tools, or use CAPTCHA validation."
        }
    },
    "FLX-024": {
        "id": "FLX-024",
        "name": "Distributed Denial of Service (DDoS) Footprint",
        "category": "Infrastructure",
        "attack_type": "DDoS Indicators",
        "severity": "CRITICAL",
        "confidence": 80,
        "description": "Extreme request throughput spikes originating from coordinated or single high-throughput IPs within a compressed timeframe.",
        "mitre": {
            "tactic": "Impact",
            "tactic_id": "TA0040",
            "technique": "Network Denial of Service",
            "technique_id": "T1498"
        },
        "owasp": "A05:2021-Security Misconfiguration",
        "recommendation": {
            "block_ip": True,
            "rate_limit": True,
            "waf_rule": "SecRule IP:DDoS_RPM \"@ge 500\" \"id:100024,deny,status:429\"",
            "remediation": "Integrate CDN/WAF defenses (Cloudflare, AWS Shield), configure keep-alive parameters, and lower server connection timeouts."
        }
    },

    # ─── Other Enterprise Threats ─────────────────────────────────────────────
    "FLX-025": {
        "id": "FLX-025",
        "name": "Sensitive Data Exposure Alert",
        "category": "Other",
        "attack_type": "Sensitive Data Exposure",
        "severity": "HIGH",
        "confidence": 80,
        "description": "Detection of sensitive patterns (credit card numbers, SSH private keys, AWS tokens, SQL error stacks) in web server response content/logs.",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Credentials from Web Browsers",
            "technique_id": "T1555"
        },
        "owasp": "A02:2021-Cryptographic Failures",
        "recommendation": {
            "block_ip": False,
            "rate_limit": False,
            "waf_rule": "SecRule RESPONSE_BODY \"@rx (---BEGIN\\s+RSA\\s+PRIVATE|\\d{4}-\\d{4}-\\d{4}-\\d{4})\" \"id:100025,deny,status:500\"",
            "remediation": "Scrub sensitive data from log files, mask sensitive outputs, and configure strict access keys/passwords storage practices."
        }
    },
    "FLX-026": {
        "id": "FLX-026",
        "name": "Authentication Bypass Probe",
        "category": "Other",
        "attack_type": "Auth Bypass",
        "severity": "HIGH",
        "confidence": 90,
        "description": "Unauthenticated access directly retrieving objects or configuration folders returning HTTP 200 without authentication cookies or tokens.",
        "mitre": {
            "tactic": "Defense Evasion",
            "tactic_id": "TA0005",
            "technique": "Bypass User Account Control",
            "technique_id": "T1548.002"
        },
        "owasp": "A01:2021-Broken Access Control",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule REQUEST_FILENAME \"@rx ^/api/admin\" \"id:100026,deny,status:401\"",
            "remediation": "Implement secure authentication middleware checks for all internal, administrative, and object endpoints."
        }
    },
    "FLX-027": {
        "id": "FLX-027",
        "name": "Privilege Escalation Intent",
        "category": "Other",
        "attack_type": "Privilege Escalation",
        "severity": "CRITICAL",
        "confidence": 95,
        "description": "Attempts to pass sudo, su, chmod, or role modification attributes within HTTP headers, cookies, or parameters.",
        "mitre": {
            "tactic": "Privilege Escalation",
            "tactic_id": "TA0004",
            "technique": "Exploitation for Privilege Escalation",
            "technique_id": "T1068"
        },
        "owasp": "A01:2021-Broken Access Control",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule ARGS:role \"@strEq admin\" \"id:100027,deny,status:403\"",
            "remediation": "Do not trust privilege attributes submitted by the client. Perform database-driven role verification on the server side."
        }
    },
    "FLX-028": {
        "id": "FLX-028",
        "name": "HTML/JS Parameter Injection",
        "category": "Other",
        "attack_type": "JS Injection",
        "severity": "HIGH",
        "confidence": 85,
        "description": "Javascript snippets injected through query fields, attempting to evaluate inside context areas.",
        "mitre": {
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "technique": "Exploit Public-Facing Application",
            "technique_id": "T1190"
        },
        "owasp": "A03:2021-Injection",
        "recommendation": {
            "block_ip": True,
            "rate_limit": False,
            "waf_rule": "SecRule ARGS \"@rx (eval\\(|javascript:|onclick=)\" \"id:100028,deny,status:403\"",
            "remediation": "Enforce context-aware parameter filtering and strict output encoding templates on the frontend/backend."
        }
    },
    "FLX-029": {
        "id": "FLX-029",
        "name": "CSP Bypass Attempt",
        "category": "Other",
        "attack_type": "CSP Bypass",
        "severity": "MEDIUM",
        "confidence": 75,
        "description": "Attempts to inject data: URLs, inline scripts, or load external scripts from domains not configured in the Content Security Policy.",
        "mitre": {
            "tactic": "Defense Evasion",
            "tactic_id": "TA0005",
            "technique": "Impair Defenses: Disable or Modify Tools",
            "technique_id": "T1562.001"
        },
        "owasp": "A05:2021-Security Misconfiguration",
        "recommendation": {
            "block_ip": False,
            "rate_limit": False,
            "waf_rule": "SecRule REQUEST_HEADERS:Content-Security-Policy-Report-Only \"@rx bypass\" \"id:100029,pass\"",
            "remediation": "Implement a strict CSP that avoids 'unsafe-inline' and 'unsafe-eval', uses nonce-based execution, and restricts script-src domains."
        }
    },
    "FLX-030": {
        "id": "FLX-030",
        "name": "Weak Session ID Identifier",
        "category": "Other",
        "attack_type": "Weak Session IDs",
        "severity": "MEDIUM",
        "confidence": 70,
        "description": "Detecting session cookie formats that are too short (< 16 characters), sequential, or numeric only.",
        "mitre": {
            "tactic": "Credential Access",
            "tactic_id": "TA0006",
            "technique": "Steal Web Session Cookie",
            "technique_id": "T1539"
        },
        "owasp": "A02:2021-Cryptographic Failures",
        "recommendation": {
            "block_ip": False,
            "rate_limit": False,
            "waf_rule": "SecRule REQUEST_HEADERS:Cookie \"@rx sessionid=\\d{1,8}$\" \"id:100030,pass\"",
            "remediation": "Generate session identifiers using secure, cryptographically random generators (e.g., secrets module in Python) of at least 128-bits."
        }
    }
}
