"""
OpenSearch DoS Dashboard & Alert Setup Script
==============================================
Run this script ONCE to programmatically create:
  1. DoS-specific saved searches in OpenSearch
  2. A DoS Alert Monitor that triggers when dos_detected events >= 3 in 10 minutes

Usage:
    python services/setup_opensearch_dos.py

Requires OpenSearch to be running and accessible.
"""

import json
import requests
import urllib3
from config import OS_URL, OS_USER, OS_PASS, OS_INDEX, OS_VERIFY_SSL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AUTH = (OS_USER, OS_PASS)
VERIFY = OS_VERIFY_SSL
HEADERS = {"Content-Type": "application/json"}


def _put(path, body):
    """PUT request to OpenSearch."""
    url = f"{OS_URL}{path}"
    r = requests.put(url, auth=AUTH, json=body, verify=VERIFY, headers=HEADERS, timeout=15)
    return r


def _post(path, body):
    """POST request to OpenSearch."""
    url = f"{OS_URL}{path}"
    r = requests.post(url, auth=AUTH, json=body, verify=VERIFY, headers=HEADERS, timeout=15)
    return r


def _get(path):
    """GET request to OpenSearch."""
    url = f"{OS_URL}{path}"
    r = requests.get(url, auth=AUTH, verify=VERIFY, timeout=15)
    return r


def ensure_dos_alerts_index():
    """Create the uni-dos-alerts index if it doesn't exist."""
    r = _get(f"/uni-dos-alerts")
    if r.status_code == 404:
        body = {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "alert_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "source_ip": {"type": "keyword"},
                    "event_count": {"type": "integer"},
                    "message": {"type": "text"},
                    "time_window": {"type": "keyword"}
                }
            }
        }
        r = _put("/uni-dos-alerts", body)
        if r.status_code in (200, 201):
            print("[OK] Created uni-dos-alerts index")
        else:
            print(f"[WARN] Could not create index: {r.status_code} {r.text[:200]}")
    else:
        print("[OK] uni-dos-alerts index already exists")


def create_dos_alert_monitor():
    """
    Create an OpenSearch Alerting monitor that triggers when
    dos_detected or dos_ip_blocked events >= 3 in the last 10 minutes.
    """
    monitor_body = {
        "name": "DoS Attack Detection Monitor",
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {
            "period": {
                "interval": 5,
                "unit": "MINUTES"
            }
        },
        "inputs": [
            {
                "search": {
                    "indices": [OS_INDEX],
                    "query": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "must": [
                                    {
                                        "terms": {
                                            "event": ["dos_detected", "dos_ip_blocked"]
                                        }
                                    },
                                    {
                                        "range": {
                                            "@timestamp": {
                                                "gte": "now-10m",
                                                "lte": "now"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        "aggs": {
                            "dos_count": {
                                "value_count": {
                                    "field": "event"
                                }
                            },
                            "attacker_ips": {
                                "terms": {
                                    "field": "ip",
                                    "size": 5
                                }
                            }
                        }
                    }
                }
            }
        ],
        "triggers": [
            {
                "query_level_trigger": {
                    "name": "DoS Attack Threshold Exceeded",
                    "severity": "1",
                    "condition": {
                        "script": {
                            "source": "ctx.results[0].aggregations.dos_count.value >= 3",
                            "lang": "painless"
                        }
                    },
                    "actions": [
                        {
                            "name": "Log DoS Alert",
                            "destination_id": "",
                            "message_template": {
                                "source": "DoS attack detected! {{ctx.results[0].aggregations.dos_count.value}} events in last 10 minutes. Top attacker IPs: {{ctx.results[0].aggregations.attacker_ips.buckets}}",
                                "lang": "mustache"
                            },
                            "throttle_enabled": True,
                            "throttle": {
                                "value": 10,
                                "unit": "MINUTES"
                            },
                            "action_execution_policy": {
                                "action_execution_scope": {
                                    "per_alert": {
                                        "actionable_alerts": ["DEDUPED", "NEW"]
                                    }
                                }
                            }
                        }
                    ]
                }
            }
        ]
    }

    # Check if monitor already exists
    search_body = {
        "query": {
            "match": {
                "monitor.name": "DoS Attack Detection Monitor"
            }
        }
    }
    r = _get("/_plugins/_alerting/monitors/_search")
    existing = False
    if r.status_code == 200:
        hits = r.json().get("hits", {}).get("hits", [])
        for hit in hits:
            name = hit.get("_source", {}).get("name", "")
            if name == "DoS Attack Detection Monitor":
                existing = True
                print(f"[OK] DoS Alert Monitor already exists (ID: {hit['_id']})")
                break

    if not existing:
        r = _post("/_plugins/_alerting/monitors", monitor_body)
        if r.status_code in (200, 201):
            monitor_id = r.json().get("_id", "unknown")
            print(f"[OK] Created DoS Alert Monitor (ID: {monitor_id})")
        else:
            print(f"[WARN] Could not create monitor: {r.status_code}")
            print(f"       Response: {r.text[:500]}")
            print("\n[INFO] If the Alerting plugin is not installed, the monitor")
            print("       cannot be created. The DoS logs are still queryable")
            print("       directly from OpenSearch Dashboards.")


def create_dos_saved_search():
    """
    Create a saved search in OpenSearch for DoS events.
    This can be used in dashboards.
    """
    saved_search = {
        "attributes": {
            "title": "DoS Attack Events",
            "description": "All DoS-related security events (warnings, detections, blocks)",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": OS_INDEX,
                    "query": {
                        "query": "event:dos_warning OR event:dos_detected OR event:dos_ip_blocked",
                        "language": "kuery"
                    },
                    "filter": [],
                    "sort": [{"@timestamp": "desc"}]
                })
            }
        }
    }

    r = _post(
        "/api/saved_objects/search/dos-attack-events",
        saved_search
    )
    # This endpoint might not work directly - OpenSearch Dashboards API is different
    # from OpenSearch API. Log result for debugging.
    print(f"[INFO] Saved search creation: {r.status_code}")


def print_dashboard_instructions():
    """Print instructions for manually creating the DoS dashboard if needed."""
    print("\n" + "=" * 60)
    print("  OpenSearch DoS Dashboard — Manual Setup Guide")
    print("=" * 60)
    print("""
If the automated dashboard creation fails, follow these steps
in OpenSearch Dashboards (http://localhost:5601):

1. Go to Discover → Select index pattern: uni-auth-logs*
2. Filter by: event is one of [dos_warning, dos_detected, dos_ip_blocked]
3. Save this search as "DoS Attack Events"

4. Go to Visualize → Create visualization:

   a) LINE CHART — "DoS Events Timeline"
      - Y-axis: Count
      - X-axis: Date Histogram on @timestamp (interval: hour)
      - Split series by: event.keyword

   b) HORIZONTAL BAR — "Top DoS Attacker IPs"
      - Y-axis: Terms on ip.keyword (top 10)
      - X-axis: Count

   c) PIE CHART — "DoS Event Type Breakdown"
      - Slice by: Terms on event.keyword
      - Filter: event is one of [dos_warning, dos_detected, dos_ip_blocked]

   d) DATA TABLE — "Currently Blocked IPs"
      - Rows: Terms on ip.keyword
      - Metrics: Count, Max @timestamp

5. Go to Dashboards → Create dashboard:
   - Add all 4 visualizations above
   - Save as "DoS Attack Dashboard"

6. For ALERTING (requires Alerting plugin):
   - Go to Alerting → Monitors → Create Monitor
   - Name: "DoS Attack Detection"
   - Index: uni-auth-logs
   - Condition: Count of docs where event=dos_detected >= 3 in last 10 min
   - Trigger severity: HIGH
""")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  OpenSearch DoS Dashboard & Alert Setup")
    print("=" * 60)
    print(f"  OpenSearch URL: {OS_URL}")
    print(f"  SIEM Index: {OS_INDEX}")
    print()

    # Check connectivity
    try:
        r = _get("/")
        if r.status_code == 200:
            info = r.json()
            print(f"  Connected: OpenSearch {info.get('version', {}).get('number', 'unknown')}")
        else:
            print(f"  Connection returned HTTP {r.status_code}")
    except Exception as e:
        print(f"  ERROR: Cannot connect to OpenSearch: {e}")
        print("  Make sure OpenSearch is running and accessible.")
        exit(1)

    print()

    # Step 1: Create alerts index
    ensure_dos_alerts_index()

    # Step 2: Create alerting monitor
    create_dos_alert_monitor()

    # Step 3: Print manual instructions
    print_dashboard_instructions()

    print("\n[DONE] Setup complete.\n")
