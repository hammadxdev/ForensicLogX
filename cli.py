#!/usr/bin/env python3
"""
ForensicLogX — Command Line Interface
Usage: python cli.py <command> [options]

Legacy mode (backward-compatible):
    python cli.py logs/sample/demo_apache_access.log

CRS commands:
    python cli.py load-crs                     Load/reload CRS rules
    python cli.py analyze-log <file>           Scan log file with CRS detection
    python cli.py rule-info <rule_id>          Show details for a specific rule
    python cli.py attack-report [--last-24h]  Generate attack report
"""

import argparse
import sys
import os
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(__file__))

from backend.parser         import parse_log_file, get_summary
from backend.threat_engine  import run_all_detections
from backend.integrity      import compute_sha256, save_hash, ChainOfCustody
from backend.ip_blocker     import generate_rules, apply_rules
from backend.report_generator import generate_pdf_report
from backend.config         import Config


def color(text, code): return f"\033[{code}m{text}\033[0m"
def red(t):    return color(t, 31)
def green(t):  return color(t, 32)
def yellow(t): return color(t, 33)
def cyan(t):   return color(t, 36)
def bold(t):   return color(t, 1)
def magenta(t): return color(t, 35)


# ═══════════════════════════════════════════════════════════════════════════════
#  CRS COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_load_crs(args):
    """Load and parse CRS rules into the SQLite database."""
    print()
    print(bold("=" * 60))
    print(bold("  ForensicLogX — CRS Rule Loader"))
    print(bold("=" * 60))
    print()

    from backend.crs_parser import CRSParser, RULES_DIR, DB_PATH
    print(cyan(f"[CRS] Rules directory : {RULES_DIR}"))
    print(cyan(f"[CRS] Database path   : {DB_PATH}"))
    print()

    parser = CRSParser()
    pl = getattr(args, 'paranoia_level', 2)

    print(cyan(f"[CRS] Loading rules (paranoia level <= {pl})..."))
    count = parser.load_rules(paranoia_level=pl)

    stats = parser.get_stats()
    print(f"\n  {green('OK')} Loaded {bold(str(count))} rules\n")
    print("  Category breakdown:")
    for cat, n in stats["by_category"].items():
        bar = "#" * min(n // 2, 40)
        print(f"    {cat:<28}  {cyan(str(n).rjust(4))}  {bar}")

    print("\n  Severity breakdown:")
    sev_colors = {"CRITICAL": red, "HIGH": yellow, "MEDIUM": cyan, "LOW": green}
    for sev, n in stats["by_severity"].items():
        col = sev_colors.get(sev, str)
        print(f"    {col(sev.ljust(10))}  {n}")

    print()
    print(bold("=" * 60))
    print(bold("  CRS rules loaded successfully!"))
    print(bold("=" * 60))
    print()


def cmd_analyze_log(args):
    """Scan a log file with CRS detection."""
    filepath = args.file
    if not os.path.exists(filepath):
        print(red(f"[ERROR] File not found: {filepath}"))
        sys.exit(1)

    print()
    print(bold("=" * 60))
    print(bold("  ForensicLogX — CRS Log Analyzer"))
    print(bold("=" * 60))
    print()

    from backend.crs_detector import CRSDetector
    from backend.attack_categorizer import AttackCategorizer

    print(cyan("[1/3] Loading CRS detection engine..."))
    detector = CRSDetector()
    pl       = getattr(args, 'paranoia_level', 2)
    n_rules  = detector.load(paranoia_level=pl)
    print(f"      Loaded {green(str(n_rules))} CRS patterns")

    print(cyan(f"\n[2/3] Scanning: {filepath}"))
    save = not getattr(args, 'no_save', False)
    alerts = detector.analyze_file(filepath, save=save, paranoia_level=pl)

    print(cyan(f"\n[3/3] Categorising {len(alerts)} alerts..."))
    cat = AttackCategorizer()
    enriched  = cat.enrich_batch(alerts)
    chains    = cat.detect_chains(alerts)
    campaigns = cat.summarise_by_ip(alerts)

    # ── Print results ─────────────────────────────────────────────────────────
    sev_colors = {"CRITICAL": red, "HIGH": yellow, "MEDIUM": cyan, "LOW": green}

    if enriched:
        print(f"\n  {bold('THREATS DETECTED: ' + str(len(enriched)))}")
        print(f"  {'Severity':<10} {'Rule':<8} {'Category':<20} {'Description'}")
        print("  " + "-" * 70)
        for a in enriched[:50]:   # cap terminal output
            col = sev_colors.get(a["severity"], str)
            desc = a.get("description", "")[:45]
            print(f"  [{col(a['severity'][:4]):<12}] "
                  f"{cyan(str(a['rule_id'])):<12}"
                  f"{a['category']:<22}{desc}")
        if len(enriched) > 50:
            print(f"  ... and {len(enriched) - 50} more alerts")
    else:
        print(f"\n  {green('No CRS threats detected.')}")

    if chains:
        print(f"\n  {bold('ATTACK CHAINS DETECTED:')}")
        for ch in chains:
            print(f"    [{red('CHAIN')}] {ch['chain_name']} — IP: {ch['source_ip']}")

    if campaigns:
        print(f"\n  {bold('TOP ATTACKER IPs:')}")
        for c in campaigns[:5]:
            print(f"    {c['source_ip']:<18} alerts={c['total_alerts']}  "
                  f"risk={c['risk_score']}/100  "
                  f"cats={', '.join(c['categories'].keys())}")

    # ── Export JSON ───────────────────────────────────────────────────────────
    if getattr(args, 'output_json', None):
        out = {
            "file": filepath,
            "scanned": datetime.now().isoformat(),
            "total_alerts": len(enriched),
            "alerts": enriched,
            "chains": chains,
            "campaigns": campaigns,
        }
        with open(args.output_json, "w") as f:
            json.dump(out, f, indent=2)
        print(f"\n  {green('Report saved:')} {args.output_json}")

    print()
    print(bold("=" * 60))
    print(bold(f"  Scan complete!  {len(enriched)} alerts  |  {len(chains)} chains"))
    print(bold("=" * 60))
    print()


def cmd_rule_info(args):
    """Show details for a specific CRS rule ID."""
    rule_id = args.rule_id

    from backend.crs_parser import CRSParser
    from backend.attack_categorizer import AttackCategorizer

    parser = CRSParser()
    rule   = parser.get_rule(rule_id)

    if not rule:
        # Try loading first
        print(yellow(f"Rule {rule_id} not in cache — loading rules..."))
        parser.load_rules(paranoia_level=4)
        rule = parser.get_rule(rule_id)

    if not rule:
        print(red(f"[ERROR] Rule {rule_id} not found in CRS database."))
        print(yellow("  Tip: Run 'python cli.py load-crs' first."))
        sys.exit(1)

    cat   = AttackCategorizer()
    mitre = cat._lookup_mitre(rule_id)

    print()
    print(bold("=" * 60))
    print(bold(f"  CRS Rule {rule_id}"))
    print(bold("=" * 60))
    print()
    print(f"  {'Description':<20}: {rule['description']}")
    print(f"  {'Category':<20}: {cyan(rule['category'])}")
    sev_col = {"CRITICAL": red, "HIGH": yellow, "MEDIUM": cyan}.get(rule["severity"], green)
    print(f"  {'Severity':<20}: {sev_col(rule['severity'])}")
    print(f"  {'Paranoia Level':<20}: {rule['paranoia_level']}")
    print(f"  {'Operator':<20}: {rule['operator']}")
    print(f"  {'Phase':<20}: {rule['phase']}")
    print(f"  {'Action':<20}: {rule['action']}")
    print(f"  {'Source File':<20}: {rule['source_file']}")
    print(f"  {'CRS Version':<20}: {rule['crs_version']}")
    if rule.get("capec"):
        print(f"  {'CAPEC':<20}: CAPEC-{rule['capec']}")

    if mitre:
        print()
        print(bold("  MITRE ATT&CK:"))
        print(f"    {'Technique ID':<18}: {mitre.get('technique_id','')}")
        print(f"    {'Technique':<18}: {mitre.get('technique_name','')}")
        print(f"    {'Tactic':<18}: {mitre.get('tactic','')} ({mitre.get('tactic_id','')})")
        if mitre.get("cve"):
            print(f"    {'CVE':<18}: {mitre['cve']}")
        print(f"    {'Reference':<18}: {mitre.get('mitre_url','')}")

    if rule.get("pattern"):
        print()
        print(bold("  Detection Pattern:"))
        pat = rule["pattern"]
        print(f"    {pat[:120]}{'...' if len(pat) > 120 else ''}")

    tags = rule.get("tags", [])
    if isinstance(tags, str):
        import json as _json
        tags = _json.loads(tags)
    if tags:
        print()
        print(f"  {'Tags':<20}: {', '.join(tags[:8])}")

    print()


def cmd_attack_report(args):
    """Generate an attack report from the alerts database."""
    from backend.crs_detector import CRSDetector
    from backend.attack_categorizer import AttackCategorizer
    import sqlite3
    from backend.crs_parser import DB_PATH

    print()
    print(bold("=" * 60))
    print(bold("  ForensicLogX — CRS Attack Report"))
    print(bold("=" * 60))
    print()

    detector = CRSDetector()

    # Get alerts — optionally filter to last 24h
    limit = 5000
    all_alerts = detector.get_recent_alerts(limit=limit)

    if getattr(args, 'last_24h', False):
        cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat() + "Z"
        all_alerts = [a for a in all_alerts if a.get("timestamp", "") >= cutoff]
        print(cyan(f"  Showing alerts from last 24 hours (cutoff: {cutoff[:16]} UTC)"))
    else:
        print(cyan(f"  Showing last {len(all_alerts)} alerts"))

    cat      = AttackCategorizer()
    stats    = detector.get_attack_stats()
    enriched = cat.enrich_batch(all_alerts)
    chains   = cat.detect_chains(all_alerts)
    campaigns = cat.summarise_by_ip(all_alerts)

    print()
    print(bold("  -- Summary --"))
    print(f"  Total Alerts   : {bold(str(stats.get('total_alerts', 0)))}")
    print()

    print(bold("  -- By Category --"))
    for cat_name, n in stats.get("by_category", {}).items():
        bar = "#" * min(n, 30)
        print(f"  {cat_name:<22}  {cyan(str(n).rjust(5))}  {bar}")

    print()
    print(bold("  -- By Severity --"))
    sev_colors = {"CRITICAL": red, "HIGH": yellow, "MEDIUM": cyan, "LOW": green}
    for sev, n in stats.get("by_severity", {}).items():
        col = sev_colors.get(sev, str)
        print(f"  {col(sev.ljust(10))}  {n}")

    print()
    print(bold("  -- Top Attackers --"))
    for entry in stats.get("top_attacker_ips", []):
        print(f"  {entry['ip']:<18}  {entry['count']} alerts")

    print()
    print(bold("  -- Top Triggered Rules --"))
    for rule in stats.get("top_triggered_rules", []):
        desc = rule.get("description", "")[:40]
        print(f"  Rule {cyan(str(rule['rule_id'])):<12}  "
              f"{rule['count']:>5} hits  [{rule['category']}] {desc}")

    if chains:
        print()
        print(bold("  -- Attack Chains --"))
        for ch in chains:
            print(f"  [CHAIN] {ch['chain_name']}  IP: {ch['source_ip']}")

    print()
    print(bold("=" * 60))
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  LEGACY MAIN (original CLI behaviour)
# ═══════════════════════════════════════════════════════════════════════════════

def legacy_main(logfile, analyst, report, block_all, dry_run, output_dir, export_custody):
    """Original ForensicLogX analysis flow."""
    print()
    print(bold("=" * 60))
    print(bold("  ForensicLogX — Linux Log Analyzer"))
    print(bold("  BS Digital Forensics & Cyber Security"))
    print(bold("=" * 60))
    print()

    # Step 1: Hash
    print(cyan("[1/5] Computing SHA-256 hash..."))
    file_hash = compute_sha256(logfile)
    save_hash(logfile, file_hash, Config.HASH_FOLDER)
    print(f"      Hash: {green(file_hash[:32])}...")

    # Step 2: Chain of Custody
    coc = ChainOfCustody(analyst, os.path.basename(logfile), file_hash)

    # Step 3: Parse
    print(cyan("\n[2/5] Parsing log file..."))
    df = parse_log_file(logfile)
    coc.add_entry("Log Parsing Complete", f"{len(df)} entries extracted")
    summary = get_summary(df)
    total_req_str = f"{summary['total_requests']:,}"
    print(f"      Total entries : {green(total_req_str)}")
    print(f"      Unique IPs    : {summary['unique_ips']}")
    print(f"      Error rate    : {summary['error_rate_pct']}%")

    # Step 4: Threats
    print(cyan("\n[3/5] Running threat detection engine..."))
    threats = run_all_detections(df)
    coc.add_entry("Threat Detection", f"{len(threats)} threats found")

    if threats:
        print(f"\n      {bold('THREATS DETECTED:')}")
        sev_colors = {"critical": red, "high": yellow, "medium": cyan, "low": green}
        for t in threats:
            col = sev_colors.get(t["severity"], str)
            print(f"      [{col(t['severity'].upper())}] {t['type']} — {t['ip']} — {t['detail']}")
    else:
        print(f"      {green('No threats detected.')}")

    # Step 5: IP Blocking
    if block_all:
        print(cyan("\n[4/5] Generating firewall rules..."))
        malicious = list(set(t["ip"] for t in threats if t["ip"] != "Multiple"))
        if malicious:
            rules = generate_rules(malicious)
            for r in rules["iptables_rules"]:
                print(f"      {green(r)}")
            apply_rules(malicious, dry_run=dry_run)
            coc.add_entry("IP Blocking", f"{len(malicious)} IPs {'(dry-run)' if dry_run else 'blocked'}")
            print(f"\n      Blocked {len(malicious)} IPs {'(dry-run mode)' if dry_run else '— rules applied!'}")
        else:
            print(f"      {green('No malicious IPs to block.')}")
    else:
        print(cyan("\n[4/5] IP blocking skipped (use --block-all to enable)"))

    # Step 6: Report
    if report:
        print(cyan("\n[5/5] Generating forensic PDF report..."))
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir,
                                   f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        out = generate_pdf_report(
            output_path=report_path, analyst=analyst,
            organization="BS Digital Forensics & Cyber Security",
            summary=summary, threats=threats,
            custody_entries=coc.entries, file_hash=file_hash,
            filename=os.path.basename(logfile),
        )
        print(f"      Saved: {green(out)}")
    else:
        print(cyan("\n[5/5] Report skipped (use --report to generate PDF)"))

    if export_custody:
        custody_path = coc.export_json(output_dir)
        print(f"\n{green('Chain of custody saved:')} {custody_path}")

    print()
    print(bold("=" * 60))
    print(bold("  Analysis complete!"))
    print(bold("=" * 60))
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    # Check if first argument is a CRS sub-command
    if len(sys.argv) > 1 and sys.argv[1] in ("load-crs", "analyze-log", "rule-info", "attack-report"):
        sub = sys.argv[1]
        sub_parser = argparse.ArgumentParser(
            prog=f"python cli.py {sub}",
            description={
                "load-crs":      "Load & parse CRS rules into SQLite database",
                "analyze-log":   "Scan a log file with CRS detection",
                "rule-info":     "Show details for a specific CRS rule",
                "attack-report": "Generate attack report from alerts database",
            }[sub],
        )

        if sub == "load-crs":
            sub_parser.add_argument("--paranoia-level", type=int, default=2,
                                    dest="paranoia_level",
                                    help="Paranoia level 1-4 (default: 2)")
            a = sub_parser.parse_args(sys.argv[2:])
            cmd_load_crs(a)

        elif sub == "analyze-log":
            sub_parser.add_argument("file", help="Path to Apache/Nginx log file")
            sub_parser.add_argument("--paranoia-level", type=int, default=2,
                                    dest="paranoia_level")
            sub_parser.add_argument("--no-save", action="store_true",
                                    help="Don't persist alerts to DB")
            sub_parser.add_argument("--output-json", metavar="PATH",
                                    help="Export results as JSON file")
            a = sub_parser.parse_args(sys.argv[2:])
            cmd_analyze_log(a)

        elif sub == "rule-info":
            sub_parser.add_argument("rule_id", type=int,
                                    help="CRS rule ID (e.g. 941100)")
            a = sub_parser.parse_args(sys.argv[2:])
            cmd_rule_info(a)

        elif sub == "attack-report":
            sub_parser.add_argument("--last-24h", action="store_true",
                                    dest="last_24h",
                                    help="Show only last 24 hours of alerts")
            a = sub_parser.parse_args(sys.argv[2:])
            cmd_attack_report(a)

        return

    # ── Legacy mode ────────────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        description="ForensicLogX — Forensic Linux Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Legacy mode:
  python cli.py logs/sample/demo_apache_access.log
  python cli.py access.log --analyst "Gohar Ali" --report

CRS commands:
  python cli.py load-crs
  python cli.py analyze-log access.log
  python cli.py rule-info 941100
  python cli.py attack-report --last-24h
""",
    )
    parser.add_argument("logfile",           help="Path to Apache/Nginx log file")
    parser.add_argument("--analyst",         default="Analyst")
    parser.add_argument("--report",          action="store_true")
    parser.add_argument("--block-all",       action="store_true")
    parser.add_argument("--dry-run",         action="store_true")
    parser.add_argument("--output-dir",      default="reports")
    parser.add_argument("--export-custody",  action="store_true")
    args = parser.parse_args()

    legacy_main(
        logfile=args.logfile,
        analyst=args.analyst,
        report=args.report,
        block_all=args.block_all,
        dry_run=args.dry_run,
        output_dir=args.output_dir,
        export_custody=args.export_custody,
    )


if __name__ == "__main__":
    main()
