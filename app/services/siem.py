"""
SIEM Service Module
===================
Handles log forwarding to OpenSearch and provides query functions
for the admin dashboard charts.

Log enrichment includes: request method, path, geo hints, and session
correlation hashes per NIST SP 800-92 centralized logging guidelines.
"""

import hashlib
import ipaddress
import requests
import urllib3
from datetime import datetime, timezone
from flask import request as flask_request, session
from config import OS_URL, OS_INDEX, OS_USER, OS_PASS, OS_VERIFY_SSL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_client_ip():
    return flask_request.headers.get("X-Forwarded-For", flask_request.remote_addr) or "unknown"


def get_user_agent():
    return flask_request.headers.get("User-Agent", "unknown")


def utc_iso():
    return datetime.now(timezone.utc).isoformat()


def _classify_ip(ip_str):
    """Classify an IP as private, loopback, or public (geo hint)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private:
            return "private"
        return "public"
    except (ValueError, TypeError):
        return "unknown"


def _session_hash():
    """Create a non-reversible hash of the session ID for correlation."""
    sid = session.get("_id", "") or ""
    if not sid:
        return "none"
    return hashlib.sha256(sid.encode()).hexdigest()[:12]


def send_log(event, username, role, success, reason="-", extra=None):
    """
    Forward a structured security event to OpenSearch.

    Enriched fields (NIST SP 800-92 compliant):
      - request_method, request_path: HTTP context
      - geo_hint: loopback/private/public IP classification
      - session_hash: anonymized session correlation token
    """
    ip = get_client_ip()

    doc = {
        "@timestamp": utc_iso(),
        "event": event,
        "username": username,
        "role": role,
        "ip": ip,
        "user_agent": get_user_agent(),
        "success": bool(success),
        "reason": reason,
        # Enrichment fields
        "request_method": flask_request.method if flask_request else "N/A",
        "request_path": flask_request.path if flask_request else "N/A",
        "geo_hint": _classify_ip(ip),
        "session_hash": _session_hash(),
    }
    if isinstance(extra, dict):
        doc.update(extra)

    try:
        r = requests.post(
            f"{OS_URL}/{OS_INDEX}/_doc",
            auth=(OS_USER, OS_PASS),
            json=doc,
            verify=OS_VERIFY_SSL,
            timeout=5
        )
        if r.status_code not in (200, 201):
            print("[SIEM] Failed:", r.status_code, r.text)
    except Exception as e:
        print("[SIEM] Error:", str(e))


# ═══════════════════════════════════════════════════════════════
#  SIEM Query Functions (for dashboard charts)
# ═══════════════════════════════════════════════════════════════

def _query_opensearch(body):
    """Run a search query against the SIEM index."""
    try:
        r = requests.get(
            f"{OS_URL}/{OS_INDEX}/_search",
            auth=(OS_USER, OS_PASS),
            json=body,
            verify=OS_VERIFY_SSL,
            timeout=15
        )
        return r.json()
    except Exception as e:
        print("[SIEM Query] Error:", str(e))
        return None


def query_event_counts():
    """Get event counts by type (all time)."""
    body = {
        "size": 0,
        "aggs": {
            "events": {"terms": {"field": "event", "size": 50}},
            "success_ratio": {"terms": {"field": "success"}},
        }
    }
    data = _query_opensearch(body)
    if not data:
        return {"events": [], "success": [], "total": 0}

    total = data.get("hits", {}).get("total", {}).get("value", 0)
    events = data.get("aggregations", {}).get("events", {}).get("buckets", [])
    success = data.get("aggregations", {}).get("success_ratio", {}).get("buckets", [])
    return {"events": events, "success": success, "total": total}


def query_attack_counters():
    """Get specific attack-related counters for the dashboard cards."""
    body = {
        "size": 0,
        "aggs": {
            "events": {"terms": {"field": "event", "size": 50}},
            "last_24h_failed": {
                "filter": {
                    "bool": {
                        "must": [
                            {"term": {"event": "login_failed"}},
                            {"range": {"@timestamp": {"gte": "now-24h"}}}
                        ]
                    }
                }
            },
            "dos_events": {
                "filter": {
                    "bool": {
                        "should": [
                            {"term": {"event": "dos_warning"}},
                            {"term": {"event": "dos_detected"}},
                            {"term": {"event": "dos_ip_blocked"}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            }
        }
    }
    data = _query_opensearch(body)
    if not data:
        return {
            "total_events": 0, "failed_logins": 0, "failed_logins_24h": 0,
            "ip_lockouts": 0, "account_lockouts": 0, "access_denied": 0,
            "dos_events": 0, "ai_alerts": 0
        }

    events = {b["key"]: b["doc_count"] for b in data["aggregations"]["events"]["buckets"]}
    return {
        "total_events": data["hits"]["total"]["value"],
        "failed_logins": events.get("login_failed", 0),
        "failed_logins_24h": data["aggregations"]["last_24h_failed"]["doc_count"],
        "ip_lockouts": events.get("account_locked_ip", 0) + events.get("ip_locked_login", 0),
        "account_lockouts": events.get("account_locked_user", 0),
        "access_denied": events.get("access_denied", 0),
        "dos_events": data["aggregations"]["dos_events"]["doc_count"],
        "dos_warnings": events.get("dos_warning", 0),
        "dos_detected": events.get("dos_detected", 0),
        "dos_blocked": events.get("dos_ip_blocked", 0),
        "ai_alerts": events.get("ai_alert_generated", 0),
        "login_success": events.get("login_success", 0),
        "registrations": events.get("user_register", 0),
        "reg_failed": events.get("user_register_failed", 0),
    }


def query_events_timeline(days=30):
    """Get event counts per day for a timeline chart."""
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
        "aggs": {
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "day",
                    "format": "yyyy-MM-dd"
                },
                "aggs": {
                    "by_event": {"terms": {"field": "event", "size": 20}}
                }
            }
        }
    }
    data = _query_opensearch(body)
    if not data:
        return []

    buckets = data.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    result = []
    for b in buckets:
        if b["doc_count"] == 0:
            continue
        day_events = {e["key"]: e["doc_count"] for e in b.get("by_event", {}).get("buckets", [])}
        result.append({
            "date": b["key_as_string"],
            "total": b["doc_count"],
            "failed_logins": day_events.get("login_failed", 0),
            "login_success": day_events.get("login_success", 0),
            "ip_locked": day_events.get("account_locked_ip", 0) + day_events.get("ip_locked_login", 0),
            "dos": day_events.get("dos_detected", 0) + day_events.get("dos_warning", 0),
            "ai_alerts": day_events.get("ai_alert_generated", 0),
        })
    return result


def query_top_ips(size=10):
    """Get top IPs by event count."""
    body = {
        "size": 0,
        "aggs": {
            "top_ips": {
                "terms": {"field": "ip", "size": size},
                "aggs": {
                    "failed": {
                        "filter": {"term": {"success": False}}
                    },
                    "events": {"terms": {"field": "event", "size": 10}}
                }
            }
        }
    }
    data = _query_opensearch(body)
    if not data:
        return []

    buckets = data.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
    result = []
    for b in buckets:
        events = {e["key"]: e["doc_count"] for e in b.get("events", {}).get("buckets", [])}
        result.append({
            "ip": b["key"],
            "total": b["doc_count"],
            "failed": b["failed"]["doc_count"],
            "has_dos": events.get("dos_detected", 0) + events.get("dos_warning", 0) > 0,
            "has_brute_force": events.get("account_locked_ip", 0) + events.get("ip_locked_login", 0) > 0,
        })
    return result


def query_attack_reasons(size=15):
    """Get breakdown of attack/failure reasons."""
    body = {
        "size": 0,
        "query": {"term": {"success": False}},
        "aggs": {
            "reasons": {"terms": {"field": "reason", "size": size}}
        }
    }
    data = _query_opensearch(body)
    if not data:
        return []

    return data.get("aggregations", {}).get("reasons", {}).get("buckets", [])


def query_recent_events(limit=25):
    """Get the most recent SIEM events for the live log feed."""
    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": [
            "@timestamp", "event", "username", "role", "ip",
            "success", "reason", "request_method", "request_path", "geo_hint"
        ]
    }
    data = _query_opensearch(body)
    if not data:
        return []

    events = []
    for hit in data.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        events.append({
            "timestamp": src.get("@timestamp", ""),
            "event": src.get("event", ""),
            "username": src.get("username", ""),
            "role": src.get("role", ""),
            "ip": src.get("ip", ""),
            "success": src.get("success", True),
            "reason": src.get("reason", ""),
            "method": src.get("request_method", ""),
            "path": src.get("request_path", ""),
            "geo": src.get("geo_hint", ""),
        })
    return events


# ═══════════════════════════════════════════════════════════════
#  DoS-Specific Query Functions
# ═══════════════════════════════════════════════════════════════

def query_dos_timeline(hours=168):
    """Get DoS event counts per hour for the last 7 days."""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                    {"terms": {"event": ["dos_warning", "dos_detected", "dos_ip_blocked"]}}
                ]
            }
        },
        "aggs": {
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h",
                    "format": "yyyy-MM-dd HH:mm"
                },
                "aggs": {
                    "by_event": {"terms": {"field": "event", "size": 5}}
                }
            }
        }
    }
    data = _query_opensearch(body)
    if not data:
        return []

    buckets = data.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    result = []
    for b in buckets:
        if b["doc_count"] == 0:
            continue
        evts = {e["key"]: e["doc_count"] for e in b.get("by_event", {}).get("buckets", [])}
        result.append({
            "time": b["key_as_string"],
            "warnings": evts.get("dos_warning", 0),
            "detected": evts.get("dos_detected", 0),
            "blocked": evts.get("dos_ip_blocked", 0),
            "total": b["doc_count"],
        })
    return result


def query_dos_top_attackers(size=10):
    """Get top IPs involved in DoS events."""
    body = {
        "size": 0,
        "query": {
            "terms": {"event": ["dos_warning", "dos_detected", "dos_ip_blocked"]}
        },
        "aggs": {
            "top_ips": {
                "terms": {"field": "ip", "size": size},
                "aggs": {
                    "by_event": {"terms": {"field": "event", "size": 5}},
                    "latest": {"max": {"field": "@timestamp"}}
                }
            }
        }
    }
    data = _query_opensearch(body)
    if not data:
        return []

    buckets = data.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
    result = []
    for b in buckets:
        evts = {e["key"]: e["doc_count"] for e in b.get("by_event", {}).get("buckets", [])}
        result.append({
            "ip": b["key"],
            "total": b["doc_count"],
            "warnings": evts.get("dos_warning", 0),
            "detected": evts.get("dos_detected", 0),
            "blocked": evts.get("dos_ip_blocked", 0),
            "last_seen": b.get("latest", {}).get("value_as_string", ""),
        })
    return result
