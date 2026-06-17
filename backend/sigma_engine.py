"""
ForensicLogX — Native Sigma Rules Engine
Recursively loads Sigma rules, extracts log fields, and matches them in real-time.
Final Year Project
"""

import os
import re
import time
import pickle
import yaml

# Standard regex to parse Apache Access logs
LOG_RE = re.compile(
    r'(?:(?P<vhost>\S+)\s+)?'
    r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# Top-level directory names that can never contain web/apache/nginx/modsec rules.
# Pruning these avoids walking thousands of irrelevant files.
_SKIP_DIRS = frozenset({
    'windows', 'macos', 'cloud', 'identity',
    'create_remote_thread', 'create_stream_hash',
    'dns_query', 'driver_load', 'image_load',
    'network_connection', 'pipe_created', 'powershell',
    'process_access', 'process_creation', 'process_tampering',
    'raw_access_thread', 'registry', 'sysmon', 'wmi_event',
    'builtin',
})

# Cache file placed next to the sigma dataset directory.
_CACHE_FILE = None  # resolved lazily the first time


def _get_cache_path(base_path: str) -> str:
    parent = os.path.dirname(os.path.abspath(base_path))
    return os.path.join(parent, ".sigma_cache.pkl")


def _cache_is_valid(base_path: str, cache_path: str) -> bool:
    """Return True when the pickle cache is newer than every YAML file in base_path."""
    if not os.path.exists(cache_path):
        return False
    cache_mtime = os.path.getmtime(cache_path)
    for root, dirs, files in os.walk(base_path):
        # Prune irrelevant dirs for speed
        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS]
        for f in files:
            if f.endswith(('.yml', '.yaml')):
                if os.path.getmtime(os.path.join(root, f)) > cache_mtime:
                    return False
    return True


def load_sigma_rules(base_path):
    """
    Recursively scans the directory for Sigma .yml/.yaml rules.
    Filters and loads only web/webserver/apache/nginx/modsecurity rules.

    Performance improvements
    ------------------------
    1. Directory pruning  — entire subtrees that can never be relevant
       (windows, macos, cloud, …) are skipped before any file I/O.
    2. Pickle cache       — filtered rules are serialised to a .pkl file
       beside the dataset folder. Subsequent startups load the cache
       instantly (typically < 0.1 s) and only rebuild when a source
       .yml file is newer than the cache.
    """
    rules = []
    if not os.path.exists(base_path):
        return rules

    cache_path = _get_cache_path(base_path)

    # ── Fast path: return cached rules if still valid ─────────────────────────
    if _cache_is_valid(base_path, cache_path):
        try:
            with open(cache_path, 'rb') as fh:
                rules = pickle.load(fh)
            print(f"[Sigma Engine] Loaded {len(rules)} rules from cache (instant).")
            return rules
        except Exception as e:
            print(f"[Sigma Engine] Cache read failed ({e}), rebuilding…")

    # ── Slow path: walk and parse, then write cache ────────────────────────────
    t0 = time.monotonic()
    for root, dirs, files in os.walk(base_path):
        # Prune whole directories we know are irrelevant — this is the biggest
        # win: we never even descend into thousands of Windows / macOS rules.
        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS]

        root_lower = root.lower()
        for file in files:
            if not file.endswith(('.yml', '.yaml')):
                continue

            file_path = os.path.join(root, file)
            is_web_file = (
                file.startswith('web_') or
                'web' in root_lower or
                'apache' in root_lower or
                'nginx' in root_lower or
                'modsecurity' in root_lower
            )

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    data = yaml.safe_load(f)
                if not data or not isinstance(data, dict):
                    continue
                if 'title' not in data or 'detection' not in data:
                    continue

                logsource = data.get('logsource', {})
                category = str(logsource.get('category', '')).lower()
                product  = str(logsource.get('product',  '')).lower()

                is_relevant = (
                    is_web_file or
                    category in ('webserver', 'apache', 'nginx', 'iis', 'modsecurity', 'web') or
                    product  in ('apache', 'nginx', 'iis', 'modsecurity')
                )

                if is_relevant:
                    data['_file_path'] = file_path
                    data['_rel_path'] = os.path.relpath(file_path, base_path).replace('\\', '/')
                    rules.append(data)
            except Exception as e:
                print(f"[Sigma Engine] Warning: Failed to parse {file_path}: {e}")

    elapsed = time.monotonic() - t0
    print(f"[Sigma Engine] Loaded {len(rules)} relevant Sigma rules in {elapsed:.1f}s.")

    # Persist cache for next startup
    try:
        with open(cache_path, 'wb') as fh:
            pickle.dump(rules, fh, protocol=pickle.HIGHEST_PROTOCOL)
        print(f"[Sigma Engine] Cache written to {cache_path}")
    except Exception as e:
        print(f"[Sigma Engine] Warning: Could not write cache: {e}")

    return rules

def extract_fields(raw_line, log_type):
    """
    Extracts and standardizes fields from Apache access logs or error logs.
    """
    fields = {}
    raw_line_stripped = raw_line.strip()
    fields['raw_log'] = raw_line_stripped
    
    if log_type == 'vulnlab_access':
        m = LOG_RE.match(raw_line_stripped)
        if m:
            d = m.groupdict()
            url = d.get("url", "-")
            stem = url.split('?')[0] if '?' in url else url
            query = url.split('?')[1] if '?' in url else ""
            fields.update({
                'c-ip': d.get("ip", "-"),
                'ip': d.get("ip", "-"),
                'cs-method': d.get("method", "-"),
                'method': d.get("method", "-"),
                'cs-uri': url,
                'url': url,
                'cs-uri-stem': stem,
                'cs-uri-query': query,
                'sc-status': d.get("status", "-"),
                'status': d.get("status", "-"),
                'cs-user-agent': d.get("agent") or "-",
                'useragent': d.get("agent") or "-",
                'user-agent': d.get("agent") or "-",
                'c-useragent': d.get("agent") or "-",
                'sc-bytes': d.get("bytes", "-")
            })
    elif log_type == 'vulnlab_error':
        # Parse client IP
        ip_match = re.search(r'\[client\s+([\d\.]+)(?::\d+)?\]', raw_line_stripped)
        ip = ip_match.group(1) if ip_match else "127.0.0.1"
        
        # Parse ModSecurity rule ID
        rule_match = re.search(r'\[id\s+"(\d+)"\]', raw_line_stripped)
        rule_id = rule_match.group(1) if rule_match else ""
        
        # Parse ModSecurity log message
        msg_match = re.search(r'\[msg\s+"([^"]+)"\]', raw_line_stripped)
        msg = msg_match.group(1) if msg_match else ""
        
        fields.update({
            'c-ip': ip,
            'ip': ip,
            'rule_id': rule_id,
            'message': msg if msg else raw_line_stripped,
            'sc-status': '403' if 'ModSecurity' in raw_line_stripped else '-',
            'status': '403' if 'ModSecurity' in raw_line_stripped else '-'
        })
        
    return fields

def match_field_value(log_val, expected_val, modifiers):
    """Matches a log field value against an expected value, supporting modifiers."""
    if isinstance(expected_val, list):
        return any(match_single_value(log_val, ev, modifiers) for ev in expected_val)
    return match_single_value(log_val, expected_val, modifiers)

def match_single_value(log_val, ev, modifiers):
    """Helper to check a single value string match with modifiers."""
    log_val_str = str(log_val).lower() if log_val is not None else ""
    ev_str = str(ev).lower() if ev is not None else ""
    
    if 'contains' in modifiers:
        return ev_str in log_val_str
    elif 'startswith' in modifiers:
        return log_val_str.startswith(ev_str)
    elif 'endswith' in modifiers:
        return log_val_str.endswith(ev_str)
    else:
        return log_val_str == ev_str

def evaluate_dict(d, fields):
    """Evaluates a dictionary of selections against the log fields (logical AND of keys)."""
    FIELD_MAPPING = {
        'cs-method': 'cs-method',
        'method': 'cs-method',
        'cs-uri': 'cs-uri',
        'cs-uri-query': 'cs-uri-query',
        'cs-uri-stem': 'cs-uri-stem',
        'url': 'cs-uri',
        'sc-status': 'sc-status',
        'status': 'sc-status',
        'cs-user-agent': 'cs-user-agent',
        'useragent': 'cs-user-agent',
        'user-agent': 'cs-user-agent',
        'c-useragent': 'cs-user-agent',
        'c-ip': 'c-ip',
        'ip': 'c-ip'
    }
    
    for key, val in d.items():
        parts = key.split('|')
        base_field = parts[0]
        modifiers = parts[1:] if len(parts) > 1 else []
        
        mapped_key = FIELD_MAPPING.get(base_field.lower(), base_field.lower())
        log_val = fields.get(mapped_key)
        
        if not match_field_value(log_val, val, modifiers):
            return False
            
    return True

def evaluate_identifier(ident_name, ident_val, fields):
    """Evaluates a single search identifier against the extracted log fields."""
    # List of strings (keywords)
    if isinstance(ident_val, list) and all(isinstance(x, str) for x in ident_val):
        raw_log = fields.get('raw_log', '').lower()
        return any(kw.lower() in raw_log for kw in ident_val)
        
    # List of dicts (OR combination of selections)
    if isinstance(ident_val, list) and all(isinstance(x, dict) for x in ident_val):
        return any(evaluate_dict(d, fields) for d in ident_val)
        
    # Single dict (AND combination of selections)
    if isinstance(ident_val, dict):
        return evaluate_dict(ident_val, fields)
        
    # Single string (keyword check)
    if isinstance(ident_val, str):
        raw_log = fields.get('raw_log', '').lower()
        return ident_val.lower() in raw_log
        
    return False

def evaluate_condition_str(condition, eval_results):
    """
    Parses and evaluates a Sigma condition string using evaluated identifier states.
    Handles '1 of X', 'all of X', 'any of X', and wildcard patterns.
    """
    # 1. Expand composite terms: e.g. "1 of filter_main_*", "all of selection_*"
    def replace_of(match):
        op = match.group(1).lower()
        pattern = match.group(2)
        
        is_wildcard = pattern.endswith('*')
        base_pattern = pattern[:-1] if is_wildcard else pattern
        
        matched_keys = []
        for k in eval_results.keys():
            if is_wildcard:
                if k.lower().startswith(base_pattern.lower()):
                    matched_keys.append(k)
            else:
                if k.lower() == base_pattern.lower():
                    matched_keys.append(k)
                    
        if not matched_keys:
            return "False"
            
        if op in ('1', 'any'):
            return "(" + " or ".join(matched_keys) + ")"
        elif op == 'all':
            return "(" + " and ".join(matched_keys) + ")"
        return "False"
        
    # Run substitution for composite "of" expressions
    cond_expanded = re.sub(r'\b(1|any|all)\s+of\s+([a-zA-Z0-9_\-\*]+)', replace_of, condition, flags=re.IGNORECASE)
    
    # Sort keys by descending length to prevent sub-string collision during replacements
    sorted_keys = sorted(eval_results.keys(), key=len, reverse=True)
    
    # Insert whitespace around parentheses for clean tokenization
    tokens_str = cond_expanded.replace('(', ' ( ').replace(')', ' ) ')
    tokens = tokens_str.split()
    
    for i, t in enumerate(tokens):
        t_lower = t.lower()
        if t_lower in ('and', 'or', 'not', '(', ')'):
            tokens[i] = t_lower
        else:
            # Check if token matches a search identifier
            matched_key = None
            for k in sorted_keys:
                if k.lower() == t.lower():
                    matched_key = k
                    break
            if matched_key is not None:
                tokens[i] = str(eval_results[matched_key])
            elif t_lower in ('true', 'false'):
                tokens[i] = str(t_lower == 'true')
            else:
                # Fallback for unrecognized tokens
                tokens[i] = "False"
                
    expr_str = " ".join(tokens)
    
    # Strict validation of tokens before eval()
    allowed_tokens = {"true", "false", "and", "or", "not", "(", ")"}
    for token in expr_str.lower().split():
        if token not in allowed_tokens:
            return False
            
    try:
        return eval(expr_str, {"__builtins__": None}, {"True": True, "False": False})
    except Exception:
        return False

def match_sigma_rules(raw_log, sigma_rules, log_type):
    """
    Evaluates raw log line against loaded Sigma rules list.
    Returns list of matching rules.
    """
    matches = []
    if not sigma_rules:
        return matches
        
    fields = extract_fields(raw_log, log_type)
    if not fields or 'ip' not in fields:
        return matches
        
    for rule in sigma_rules:
        detection = rule.get('detection', {})
        condition = detection.get('condition')
        if not condition:
            continue
            
        # Evaluate all search identifiers defined in detection
        eval_results = {}
        for ident_name, ident_val in detection.items():
            if ident_name == 'condition':
                continue
            eval_results[ident_name] = evaluate_identifier(ident_name, ident_val, fields)
            
        # Evaluate the main condition string
        if evaluate_condition_str(condition, eval_results):
            matches.append(rule)
            
    return matches
