// ── Simulated live log data ──────────────────────────────────
const ATTACK_TYPES = ['SQL Injection', 'XSS', 'Command Injection', 'Directory Traversal', 'Brute Force', 'SSRF', 'RCE', 'LFI', 'CSRF', 'XXE'];
const IPS = ['192.168.1.45', '10.0.0.112', '172.16.0.88', '185.220.101.4', '91.108.4.55', '45.33.32.156', '195.28.90.12', '23.94.245.67', '103.21.244.0', '178.62.188.57'];
const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];
const ENDPOINTS = [
  '/admin/login', '/api/users', '/api/v1/products?id=1 OR 1=1',
  '/search?q=<script>alert(1)</script>', '/etc/passwd', '/wp-admin/',
  '/../../../etc/shadow', '/api/exec?cmd=whoami', '/upload.php',
  '/api/auth/token', '/dashboard', '/api/logs', '/.env', '/config.php',
];
const STATUS_CODES = [200, 200, 200, 301, 400, 401, 403, 404, 500, 502];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

let _idCounter = 1000;

function randItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

export function generateLog() {
  const severity = randItem(SEVERITIES);
  const attackType = severity === 'info' ? null : randItem(ATTACK_TYPES);
  const status = randItem(STATUS_CODES);
  const ip = randItem(IPS);
  const method = randItem(METHODS);
  const endpoint = randItem(ENDPOINTS);
  const now = new Date();

  return {
    id: ++_idCounter,
    timestamp: now.toISOString(),
    timeDisplay: now.toLocaleTimeString('en-US', { hour12: false }),
    ip,
    method,
    endpoint,
    status,
    bytes: randInt(128, 65536),
    severity,
    attackType,
    rule: attackType ? `RULE-${randInt(9000, 9999)}` : null,
    userAgent: `Mozilla/5.0 (${randItem(['Windows NT 10.0', 'Linux x86_64', 'Macintosh'])}) AppleWebKit/537.36`,
    country: randItem(['US', 'RU', 'CN', 'DE', 'BR', 'IN', 'KR', 'UA', 'FR', 'NL']),
  };
}

// ── Alert data ───────────────────────────────────────────────
const ALERT_TITLES = {
  'SQL Injection':       'SQL Injection attempt on login endpoint',
  'XSS':                'Reflected XSS in search parameter',
  'Command Injection':   'OS Command Injection via query string',
  'Directory Traversal': 'Path Traversal to /etc/passwd',
  'Brute Force':         'Brute-force attack on /admin/login',
  'SSRF':                'SSRF exploit via redirect parameter',
  'RCE':                 'Remote Code Execution attempt',
  'LFI':                 'Local File Inclusion via include param',
  'CSRF':                'Cross-Site Request Forgery detected',
  'XXE':                 'XML External Entity injection',
};

const ANALYSTS = ['Alice Chen', 'Bob Martinez', 'Carol White', 'David Kim', 'Eve Johnson'];
const STATUSES = ['Open', 'In Progress', 'Resolved', 'False Positive'];

export function generateAlert(log) {
  const attackType = log.attackType || randItem(ATTACK_TYPES);
  return {
    id: log.id,
    timestamp: log.timestamp,
    timeDisplay: log.timeDisplay,
    severity: log.severity === 'info' ? 'low' : log.severity,
    attackType,
    title: ALERT_TITLES[attackType] || `${attackType} attack detected`,
    sourceIp: log.ip,
    endpoint: log.endpoint,
    method: log.method,
    status: STATUSES[0],
    assignedTo: null,
    rule: log.rule,
    country: log.country,
    details: `Attack pattern matched on ${log.endpoint}. Source IP: ${log.ip}. HTTP ${log.method} ${log.status}. Rule ${log.rule} triggered.`,
    expanded: false,
  };
}

// ── OWASP chart initial data ─────────────────────────────────
export const OWASP_INITIAL = ATTACK_TYPES.map(type => ({
  name: type.replace(' Injection', ' Inj.').replace('Directory Traversal', 'Dir. Traversal'),
  fullName: type,
  count: randInt(5, 150),
  color: '#' + Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0'),
}));

// Fix colors to match theme
const OWASP_COLORS = ['#ef4444','#f59e0b','#8b5cf6','#06b6d4','#10b981','#f97316','#3b82f6','#ec4899','#14b8a6','#a855f7'];
export const OWASP_DATA = ATTACK_TYPES.map((type, i) => ({
  name: type,
  shortName: type.replace(' Injection', ' Inj.').replace('Directory Traversal', 'Dir. Trav.').replace('Command Injection', 'Cmd Inj.'),
  count: randInt(10, 200),
  color: OWASP_COLORS[i],
}));

// ── Traffic chart initial data ───────────────────────────────
export function generateTrafficData(points = 20) {
  const now = Date.now();
  return Array.from({ length: points }, (_, i) => ({
    time: new Date(now - (points - i) * 30000).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
    requests: randInt(20, 200),
    attacks:  randInt(0, 30),
    blocked:  randInt(0, 15),
  }));
}

// ── IP intelligence data ─────────────────────────────────────
export const IP_DATA = IPS.map((ip, i) => ({
  ip,
  country: ['US', 'RU', 'CN', 'DE', 'BR', 'IN', 'KR', 'UA', 'FR', 'NL'][i],
  countryFlag: ['🇺🇸','🇷🇺','🇨🇳','🇩🇪','🇧🇷','🇮🇳','🇰🇷','🇺🇦','🇫🇷','🇳🇱'][i],
  requests: randInt(50, 2000),
  attacks:  randInt(5, 500),
  blocked:  Math.random() > 0.5,
  riskScore: randInt(20, 100),
  isp: ['AS-CLOUDFLARE', 'RU-QRATOR', 'ALIBABA-CN', 'HETZNER-DE', 'CLARO-BR', 'TATA-IN', 'KT-KR', 'UKRTELECOM', 'OVH-FR', 'DIGITALOCEAN'][i],
  lastSeen: new Date(Date.now() - randInt(0, 3600000)).toISOString(),
})).sort((a, b) => b.attacks - a.attacks);

// ── Detection Rules ──────────────────────────────────────────
export const RULES_DATA = [
  { id: 'RULE-9001', name: 'SQL Injection - UNION based',        category: 'SQL Injection',       severity: 'critical', enabled: true,  triggers: randInt(50,500),  description: 'Detects UNION SELECT SQL injection patterns in GET/POST parameters.' },
  { id: 'RULE-9002', name: 'SQL Injection - Boolean based',      category: 'SQL Injection',       severity: 'critical', enabled: true,  triggers: randInt(20,300),  description: 'Detects boolean-based blind SQL injection (OR 1=1, AND 1=2, etc).' },
  { id: 'RULE-9010', name: 'XSS - Reflected',                    category: 'XSS',                 severity: 'high',     enabled: true,  triggers: randInt(30,400),  description: 'Detects reflected XSS payloads in query parameters and form inputs.' },
  { id: 'RULE-9011', name: 'XSS - Stored attempt',               category: 'XSS',                 severity: 'high',     enabled: true,  triggers: randInt(10,150),  description: 'Detects stored XSS patterns in POST body and JSON payloads.' },
  { id: 'RULE-9020', name: 'Command Injection - Shell metachar',  category: 'Command Injection',   severity: 'critical', enabled: true,  triggers: randInt(5,80),    description: 'Detects shell metacharacters (;|&&) in user-supplied input.' },
  { id: 'RULE-9030', name: 'Path Traversal - ../ sequences',     category: 'Directory Traversal', severity: 'high',     enabled: true,  triggers: randInt(15,200),  description: 'Detects directory traversal sequences (../../../etc/passwd).' },
  { id: 'RULE-9040', name: 'Brute Force - Login rate limit',      category: 'Brute Force',         severity: 'medium',   enabled: true,  triggers: randInt(100,1000),description: 'Triggers when >10 failed login attempts from single IP in 60s.' },
  { id: 'RULE-9050', name: 'SSRF - Internal IP access',          category: 'SSRF',                severity: 'critical', enabled: false, triggers: randInt(2,30),    description: 'Detects SSRF attempts targeting internal IP ranges and cloud metadata.' },
  { id: 'RULE-9060', name: 'RCE - PHP code execution',           category: 'RCE',                 severity: 'critical', enabled: true,  triggers: randInt(1,20),    description: 'Detects PHP code injection and eval() exploitation attempts.' },
  { id: 'RULE-9070', name: 'LFI - File inclusion patterns',      category: 'LFI',                 severity: 'high',     enabled: true,  triggers: randInt(10,100),  description: 'Detects local file inclusion via include/require parameter manipulation.' },
  { id: 'RULE-9080', name: 'XXE - External entity declaration',  category: 'XXE',                 severity: 'high',     enabled: false, triggers: randInt(3,40),    description: 'Detects XML External Entity injection in XML/SOAP payloads.' },
  { id: 'RULE-9090', name: 'CSRF - Token missing/invalid',       category: 'CSRF',                severity: 'medium',   enabled: true,  triggers: randInt(5,60),    description: 'Detects state-changing requests without valid CSRF tokens.' },
];

// ── System health ────────────────────────────────────────────
export function generateHealth() {
  return {
    cpu:      randInt(15, 85),
    memory:   randInt(40, 90),
    logRate:  randInt(100, 2000),
    uptime:   '14d 6h 32m',
    agents:   randInt(3, 8),
  };
}
