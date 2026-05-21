"""
AI Security Analysis Module
============================
Provides AI-driven threat detection using a local LLM (Ollama).
Enhanced with per-IP behavioral analysis, velocity metrics, attack
pattern indicators, and multi-threat detection capabilities.

Follows NIST CSF Detect function and MITRE ATT&CK pattern mapping.
"""

import json
import requests
from collections import defaultdict
from config import OS_URL, OS_INDEX, OS_USER, OS_PASS
from models import get_db
from services.rate_limiter import parse_dt, now_local
from datetime import timedelta


def get_recent_logs():
    """
    Fetch the last 200 security-relevant logs from OpenSearch (last 10 minutes).
    Expanded event coverage for comprehensive threat analysis.
    """
    url = f"{OS_URL}/{OS_INDEX}/_search"
    query = {
        "size": 200,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": "now-10m", "lte": "now"}}},
                    {
                        "terms": {
                            "event": [
                                "login_failed",
                                "login_success",
                                "ip_locked_login",
                                "user_register",
                                "user_register_failed",
                                "ip_locked_registration",
                                "dos_warning",
                                "dos_detected",
                                "dos_ip_blocked",
                                "access_denied",
                                "password_reset_requested",
                                "password_reset_rate_limited",
                                "session_expired_idle",
                                "email_verification_failed",
                            ]
                        }
                    }
                ]
            }
        },
        "_source": [
            "@timestamp", "event", "username", "role", "ip",
            "success", "reason", "blocked_ip", "request_count",
            "request_method", "request_path", "geo_hint"
        ]
    }

    response = requests.get(
        url,
        auth=(OS_USER, OS_PASS),
        json=query,
        verify=False,
        timeout=10
    )
    data = response.json()

    logs = []
    for hit in data.get("hits", {}).get("hits", []):
        logs.append(hit.get("_source", {}))

    return logs


def build_security_summary(logs):
    """
    Build a comprehensive security summary with per-IP breakdowns,
    velocity metrics, and attack pattern indicators.

    This rich context enables the AI to reason about coordinated attacks
    rather than just counting raw numbers.
    """
    if not logs:
        return {
            "time_window": "last 10 minutes",
            "total_events": 0,
            "attack_indicators": [],
            "threat_level": "none",
        }

    # ── Basic event categorization ──
    failed_logins = [x for x in logs if x.get("event") == "login_failed"]
    successful_logins = [x for x in logs if x.get("event") == "login_success"]
    locked_login_ips = [x for x in logs if x.get("event") == "ip_locked_login"]
    registrations = [x for x in logs if x.get("event") == "user_register"]
    failed_registrations = [x for x in logs if x.get("event") == "user_register_failed"]
    locked_register_ips = [x for x in logs if x.get("event") == "ip_locked_registration"]
    dos_warnings = [x for x in logs if x.get("event") == "dos_warning"]
    dos_detected = [x for x in logs if x.get("event") == "dos_detected"]
    dos_blocked = [x for x in logs if x.get("event") == "dos_ip_blocked"]
    access_denied = [x for x in logs if x.get("event") == "access_denied"]
    reset_requests = [x for x in logs if x.get("event") == "password_reset_requested"]

    # ── Per-IP behavioral analysis ──
    ip_events = defaultdict(lambda: defaultdict(int))
    ip_usernames = defaultdict(set)
    for log in logs:
        ip = log.get("ip", "unknown")
        event = log.get("event", "unknown")
        ip_events[ip][event] += 1
        username = log.get("username", "")
        if username and username != "anonymous" and username != "unknown":
            ip_usernames[ip].add(username)

    # Build per-IP summary (top 10 most active IPs)
    ip_profiles = []
    for ip, events in sorted(ip_events.items(), key=lambda x: sum(x[1].values()), reverse=True)[:10]:
        total = sum(events.values())
        profile = {
            "ip": ip,
            "total_events": total,
            "event_breakdown": dict(events),
            "targeted_usernames": list(ip_usernames.get(ip, []))[:5],
        }
        ip_profiles.append(profile)

    # ── Per-username analysis (credential stuffing detection) ──
    username_ips = defaultdict(set)
    username_failures = defaultdict(int)
    for log in failed_logins:
        username = log.get("username", "")
        ip = log.get("ip", "unknown")
        if username and username != "unknown":
            username_ips[username].add(ip)
            username_failures[username] += 1

    targeted_accounts = []
    for username, ips in username_ips.items():
        targeted_accounts.append({
            "username": username,
            "failed_attempts": username_failures[username],
            "unique_source_ips": len(ips),
            "source_ips": list(ips)[:5],
        })
    targeted_accounts.sort(key=lambda x: x["failed_attempts"], reverse=True)

    # ── Attack pattern indicators ──
    attack_indicators = []

    # Brute force: single IP with many failed logins
    for ip, events in ip_events.items():
        fails = events.get("login_failed", 0)
        if fails >= 5:
            attack_indicators.append({
                "pattern": "BRUTE_FORCE",
                "description": f"IP {ip} generated {fails} failed login attempts",
                "severity": "high" if fails >= 10 else "medium",
                "source_ip": ip,
            })

    # Credential stuffing: many IPs targeting same username
    for acct in targeted_accounts:
        if acct["unique_source_ips"] >= 3:
            attack_indicators.append({
                "pattern": "CREDENTIAL_STUFFING",
                "description": f"Username '{acct['username']}' targeted from {acct['unique_source_ips']} different IPs",
                "severity": "high",
                "target": acct["username"],
            })

    # Mass registration: many registration attempts from single IP
    for ip, events in ip_events.items():
        reg_attempts = events.get("user_register_failed", 0) + events.get("user_register", 0)
        if reg_attempts >= 3:
            attack_indicators.append({
                "pattern": "MASS_REGISTRATION",
                "description": f"IP {ip} attempted {reg_attempts} registrations",
                "severity": "medium" if reg_attempts < 5 else "high",
                "source_ip": ip,
            })

    # DoS attack pattern
    dos_total = len(dos_warnings) + len(dos_detected) + len(dos_blocked)
    if dos_total >= 1:
        dos_ips = list({x.get("ip", x.get("blocked_ip", "unknown")) for x in dos_warnings + dos_detected + dos_blocked})
        attack_indicators.append({
            "pattern": "DOS_ATTACK",
            "description": f"{dos_total} DoS events detected from {len(dos_ips)} IP(s)",
            "severity": "high" if len(dos_detected) + len(dos_blocked) > 0 else "medium",
            "source_ips": dos_ips[:5],
        })

    # Password reset abuse
    if len(reset_requests) >= 3:
        reset_ips = list({x.get("ip", "unknown") for x in reset_requests})
        attack_indicators.append({
            "pattern": "PASSWORD_RESET_ABUSE",
            "description": f"{len(reset_requests)} password reset requests from {len(reset_ips)} IP(s)",
            "severity": "medium",
            "source_ips": reset_ips[:5],
        })

    # Unauthorized access attempts
    if len(access_denied) >= 2:
        attack_indicators.append({
            "pattern": "UNAUTHORIZED_ACCESS",
            "description": f"{len(access_denied)} unauthorized access attempts detected",
            "severity": "medium",
        })

    # ── Velocity metrics ──
    events_per_minute = len(logs) / 10.0  # 10-minute window

    # ── Determine threat level ──
    high_indicators = [i for i in attack_indicators if i.get("severity") == "high"]
    medium_indicators = [i for i in attack_indicators if i.get("severity") == "medium"]

    if high_indicators:
        threat_level = "high"
    elif medium_indicators:
        threat_level = "medium"
    elif attack_indicators:
        threat_level = "low"
    else:
        threat_level = "none"

    summary = {
        "time_window": "last 10 minutes",
        "total_events": len(logs),
        "events_per_minute": round(events_per_minute, 1),

        # Event counts
        "failed_logins": len(failed_logins),
        "successful_logins": len(successful_logins),
        "locked_login_ips": len(locked_login_ips),
        "registrations": len(registrations),
        "failed_registrations": len(failed_registrations),
        "locked_registration_ips": len(locked_register_ips),
        "dos_warnings": len(dos_warnings),
        "dos_detected": len(dos_detected),
        "dos_blocked_requests": len(dos_blocked),
        "access_denied": len(access_denied),
        "password_reset_requests": len(reset_requests),

        # Rich context
        "top_ip_profiles": ip_profiles[:5],
        "targeted_accounts": targeted_accounts[:5],
        "attack_indicators": attack_indicators,
        "threat_level": threat_level,
    }
    return summary


def analyze_with_ollama(summary):
    """
    Enhanced AI analysis with structured attack pattern definitions,
    multi-threat detection, confidence scoring, and actionable recommendations.

    The prompt follows MITRE ATT&CK framework terminology for consistency.
    """
    prompt = f"""You are a Senior SOC (Security Operations Center) Analyst for a university Learning Management System (LMS). Your role is to analyze security logs and identify active threats.

## ATTACK PATTERN DEFINITIONS

1. **BRUTE_FORCE** (MITRE T1110): A single IP generating 5+ failed login attempts in a short period. Indicates password guessing.
2. **CREDENTIAL_STUFFING** (MITRE T1110.004): Multiple different IPs targeting the same username with failed logins. Indicates compromised credential lists being tested.
3. **DOS_ATTACK** (MITRE T1498): Extremely high request volume from single IP exceeding rate limits. Indicated by dos_warning, dos_detected, or dos_ip_blocked events.
4. **MASS_REGISTRATION**: Multiple account creation attempts from single IP. Indicates bot-driven spam account creation.
5. **PASSWORD_RESET_ABUSE**: Excessive password reset requests. May indicate account takeover preparation.
6. **UNAUTHORIZED_ACCESS** (MITRE T1078): Attempts to access restricted resources without proper role/permissions.

## SECURITY LOG SUMMARY

```json
{json.dumps(summary, indent=2, default=str)}
```

## ANALYSIS RULES

- IGNORE normal admin activity and internal system events
- Focus ONLY on real security threats from the attack patterns above
- Each detected threat must have evidence from the logs
- Assess whether multiple indicators suggest a COORDINATED attack
- Consider the velocity (events_per_minute) as an urgency indicator

## REQUIRED RESPONSE FORMAT

Return ONLY valid JSON, no markdown, no code blocks, no explanation outside JSON:

{{
  "suspicious": true,
  "threat_count": 2,
  "threats": [
    {{
      "pattern": "BRUTE_FORCE",
      "confidence": 0.95,
      "severity": "high",
      "title": "Active Brute Force Attack",
      "summary": "IP 192.168.1.100 generated 25 failed login attempts targeting admin account",
      "source_ips": ["192.168.1.100"],
      "recommendation": "Block IP 192.168.1.100 at firewall level"
    }}
  ],
  "overall_severity": "high",
  "overall_summary": "One-line executive summary of the security situation",
  "is_coordinated": false
}}

RULES:
- suspicious must be true ONLY if real threats exist with evidence
- confidence is 0.0-1.0 (how confident you are this is a real attack)
- severity must be: low, medium, or high
- if NO threats found, return: {{"suspicious": false, "threat_count": 0, "threats": [], "overall_severity": "low", "overall_summary": "No active threats detected", "is_coordinated": false}}
- do NOT include markdown formatting or code block markers"""

    response = requests.post(
        "http://localhost:11434/api/chat",
        json={
            "model": "llama3.1:8b",
            "stream": False,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        },
        timeout=120
    )

    data = response.json()
    content = data.get("message", {}).get("content", "").strip()

    # Try direct JSON parse
    try:
        return json.loads(content), content
    except Exception:
        pass

    # Try extracting JSON from response
    try:
        start = content.find("{")
        end = content.rfind("}")
        if start != -1 and end != -1 and end > start:
            extracted = content[start:end + 1]
            return json.loads(extracted), content
    except Exception:
        pass

    # Fallback response
    fallback = {
        "suspicious": False,
        "threat_count": 0,
        "threats": [],
        "overall_severity": "low",
        "overall_summary": "AI response could not be parsed as valid JSON.",
        "is_coordinated": False
    }
    return fallback, content


def format_ai_result_for_alert(result):
    """
    Convert the multi-threat AI result into a single alert record.
    Uses the highest-severity threat for the alert title and summary.
    """
    if not result.get("suspicious") or not result.get("threats"):
        return None, None, None

    # Get overall info
    title = result.get("overall_summary", "Suspicious activity detected")[:200]
    severity = result.get("overall_severity", "medium").lower()

    # Build detailed summary from all threats
    threat_details = []
    for t in result.get("threats", []):
        conf = t.get("confidence", 0)
        threat_details.append(
            f"[{t.get('severity', 'medium').upper()}] {t.get('title', 'Unknown')} "
            f"(confidence: {conf:.0%}) — {t.get('summary', '')}"
        )

    if result.get("is_coordinated"):
        threat_details.append("⚠️ COORDINATED ATTACK: Multiple indicators suggest these threats are related.")

    # Add recommendations
    recs = []
    for t in result.get("threats", []):
        rec = t.get("recommendation")
        if rec:
            recs.append(f"→ {rec}")

    summary_text = "\n".join(threat_details)
    if recs:
        summary_text += "\n\nRecommendations:\n" + "\n".join(recs)

    return title, severity, summary_text


def save_ai_alert(title, severity, summary, raw_response):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO ai_alerts (title, severity, summary, raw_response, is_read)
        VALUES (?, ?, ?, ?, 0)
    """, (title, severity, summary, raw_response))
    conn.commit()
    conn.close()


def latest_ai_alert():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_alerts ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row
