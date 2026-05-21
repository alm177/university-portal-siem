# -*- coding: utf-8 -*-
"""
Comprehensive Attack Simulation Test Script for University Portal SIEM
=====================================================================
Tests the following attack vectors:
  1. Brute Force Login Attack (repeated failed logins -> IP lockout)
  2. Mass Registration Attack (spam registration -> IP lockout)
  3. Password Reset Abuse (repeated reset requests -> IP lockout)
  4. Unauthorized Access (accessing admin pages without login/wrong role)
  5. CAPTCHA Validation
  6. Login after lock cleared
  7. SIEM Log Verification (OpenSearch)
  8. AI Alert Trigger Check
  9. DoS Attack Simulation (rapid requests -> warning -> block)
  10. DoS Block Response Content
"""

import requests
import time
import json
import sys
import sqlite3
import os
from dotenv import load_dotenv

BASE = "http://127.0.0.1:5000"
load_dotenv()

ADMIN_USERNAME = os.environ.get("DEFAULT_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("DEFAULT_ADMIN_PASSWORD", "change-this-admin-password")
OS_USER = os.environ.get("OS_USER", "admin")
OS_PASS = os.environ.get("OS_PASS", "change-this-opensearch-password")

# Counters
passed = 0
failed = 0
warnings_list = []

def header(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")

def check(test_name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {test_name}")
    else:
        failed += 1
        print(f"  [FAIL] {test_name}")
    if detail:
        print(f"         -> {detail}")


def clear_ip_locks():
    """Clear all IP locks for a fresh test."""
    conn = sqlite3.connect("database.db")
    conn.execute("DELETE FROM ip_locks")
    conn.commit()
    conn.close()


# ===================================================================
#  TEST 1: BRUTE FORCE LOGIN ATTACK
# ===================================================================
def test_brute_force_login():
    header("TEST 1: BRUTE FORCE LOGIN ATTACK")
    print("  Simulating 7 failed login attempts (threshold=5, lock after >5)")
    clear_ip_locks()

    s = requests.Session()
    results = []

    for i in range(1, 8):
        r = s.post(f"{BASE}/login", data={
            "username": "admin",
            "password": f"WrongPass{i}!"
        }, allow_redirects=False)
        results.append(r)
        locked = "Too many failed login attempts" in r.text if r.status_code == 200 else False
        print(f"    Attempt {i}: HTTP {r.status_code} | Locked message: {locked}")

    last_resp = results[-1]
    is_locked = "Too many failed login attempts" in last_resp.text
    check("IP gets locked after exceeding login threshold",
          is_locked,
          f"Last response contains lock message: {is_locked}")

    check("Login page remains accessible (returns 200)",
          all(r.status_code == 200 for r in results),
          "All responses returned HTTP 200")

    # Verify the lockout persists - even correct password is rejected
    r = s.post(f"{BASE}/login", data={
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD
    }, allow_redirects=False)
    still_locked = "Too many failed login attempts" in r.text
    check("Correct password rejected during IP lockout",
          still_locked,
          f"Even correct creds blocked: {still_locked}")


# ===================================================================
#  TEST 2: MASS REGISTRATION ATTACK
# ===================================================================
def test_mass_registration():
    header("TEST 2: MASS REGISTRATION ATTACK")
    print("  Simulating 7 registration attempts (threshold=5, lock after >5)")
    clear_ip_locks()

    s = requests.Session()
    results = []

    for i in range(1, 8):
        # GET to get captcha in session
        s.get(f"{BASE}/register")
        r = s.post(f"{BASE}/register", data={
            "username": f"spamuser{i}",
            "email": f"spam{i}@test.com",
            "password": "Spam@1234",
            "role": "student",
            "captcha_answer": "wrong"
        }, allow_redirects=False)
        results.append(r)
        locked = "Too many registration attempts" in r.text
        print(f"    Attempt {i}: HTTP {r.status_code} | Locked: {locked}")

    last_resp = results[-1]
    is_locked = "Too many registration attempts" in last_resp.text
    check("IP gets locked after exceeding registration threshold",
          is_locked,
          f"Last response contains lock message: {is_locked}")

    # Verify lock persists on GET too
    r = s.get(f"{BASE}/register")
    locked_on_get = "Too many registration attempts" in r.text
    check("Registration page shows lock on GET request",
          locked_on_get,
          f"GET also blocked: {locked_on_get}")


# ===================================================================
#  TEST 3: PASSWORD RESET ABUSE
# ===================================================================
def test_password_reset_abuse():
    header("TEST 3: PASSWORD RESET ABUSE")
    print("  Simulating 5 password reset requests (threshold=3, window=10min)")
    clear_ip_locks()

    s = requests.Session()
    results = []

    for i in range(1, 6):
        r = s.post(f"{BASE}/forgot-password", data={
            "email": f"nonexistent{i}@test.com"
        }, allow_redirects=False)
        results.append(r)
        locked = "Too many reset requests" in r.text
        print(f"    Attempt {i}: HTTP {r.status_code} | Locked: {locked}")

    last_resp = results[-1]
    is_locked = "Too many reset requests" in last_resp.text
    check("IP gets locked after exceeding password reset threshold",
          is_locked,
          f"Last response contains lock message: {is_locked}")


# ===================================================================
#  TEST 4: UNAUTHORIZED ACCESS ATTEMPTS
# ===================================================================
def test_unauthorized_access():
    header("TEST 4: UNAUTHORIZED ACCESS ATTEMPTS")
    clear_ip_locks()

    admin_paths = ["/admin/", "/admin/users", "/admin/siem", "/admin/ai-analysis", "/admin/ai-alerts"]

    # 4a: Access admin pages without login
    print("  4a: Accessing admin pages without login...")
    s = requests.Session()
    for path in admin_paths:
        r = s.get(f"{BASE}{path}", allow_redirects=False)
        is_denied = r.status_code == 403
        check(f"Access denied for {path} (no login)",
              is_denied,
              f"HTTP {r.status_code}")

    # 4b: Access admin pages as student
    print("\n  4b: Accessing admin pages as student role...")
    s2 = requests.Session()
    r = s2.post(f"{BASE}/login", data={
        "username": "teststudent",
        "password": "Test@1234"
    }, allow_redirects=False)

    if r.status_code == 302:
        print(f"    Logged in as student 'teststudent' (redirected to {r.headers.get('Location')})")
        for path in admin_paths:
            r = s2.get(f"{BASE}{path}", allow_redirects=False)
            is_denied = r.status_code == 403
            check(f"Access denied for {path} (student role)",
                  is_denied,
                  f"HTTP {r.status_code}")
    else:
        print(f"    Could not log in as student (HTTP {r.status_code})")
        # Check if response has error text
        if "wrong" in r.text.lower() or "Too many" in r.text:
            print(f"    Response hint: {r.text[:200]}")
        for path in admin_paths:
            check(f"Access denied for {path} (student role)", False, "Student login failed")


# ===================================================================
#  TEST 5: CAPTCHA VALIDATION
# ===================================================================
def test_captcha_validation():
    header("TEST 5: CAPTCHA VALIDATION")
    clear_ip_locks()

    s = requests.Session()
    r = s.get(f"{BASE}/register")
    check("Register page loads", r.status_code == 200)

    r = s.post(f"{BASE}/register", data={
        "username": "captchatest",
        "email": "captcha@test.com",
        "password": "Test@1234",
        "role": "student",
        "captcha_answer": "999"
    }, allow_redirects=False)
    captcha_failed = "Incorrect CAPTCHA" in r.text
    check("Wrong CAPTCHA is rejected",
          captcha_failed,
          f"Contains 'Incorrect CAPTCHA': {captcha_failed}")


# ===================================================================
#  TEST 6: LOGIN WORKS AFTER LOCK CLEARED
# ===================================================================
def test_login_after_lock_clear():
    header("TEST 6: LOGIN WORKS AFTER LOCK CLEARED")
    clear_ip_locks()

    s = requests.Session()
    r = s.post(f"{BASE}/login", data={
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD
    }, allow_redirects=False)

    check("Admin login succeeds with correct credentials",
          r.status_code == 302,
          f"HTTP {r.status_code}, Location: {r.headers.get('Location', 'N/A')}")

    if r.status_code == 302:
        r2 = s.get(f"{BASE}{r.headers.get('Location', '/admin/')}", allow_redirects=False)
        check("Admin dashboard accessible after login",
              r2.status_code == 200,
              f"HTTP {r2.status_code}")


# ===================================================================
#  TEST 7: SIEM LOG VERIFICATION (OpenSearch)
# ===================================================================
def test_siem_logging():
    header("TEST 7: SIEM LOG VERIFICATION (OpenSearch)")
    print("  Checking if OpenSearch is reachable...")

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        r = requests.get(
            "https://localhost:9200",
            auth=(OS_USER, OS_PASS),
            verify=False,
            timeout=15
        )
        check("OpenSearch is reachable", r.status_code == 200, f"HTTP {r.status_code}")
    except requests.exceptions.ConnectionError:
        # Try 127.0.0.1 (IPv6 resolution issues on Windows)
        try:
            r = requests.get(
                "https://127.0.0.1:9200",
                auth=(OS_USER, OS_PASS),
                verify=False,
                timeout=15
            )
            check("OpenSearch is reachable (via 127.0.0.1)", r.status_code == 200, f"HTTP {r.status_code}")
        except Exception as e2:
            print(f"  [WARN] OpenSearch is NOT running - cannot verify SIEM logs")
            warnings_list.append(f"OpenSearch not reachable: {e2}")
            check("OpenSearch connectivity", False, str(e2))
            return

    # Use the URL that worked
    os_base = "https://127.0.0.1:9200"

    # Wait a moment for recent logs to be indexed
    time.sleep(2)

    # Check index exists
    try:
        r = requests.get(
            f"{os_base}/uni-auth-logs/_search",
            auth=(OS_USER, OS_PASS),
            json={"size": 0, "query": {"match_all": {}}},
            verify=False,
            timeout=10
        )
        data = r.json()
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        check("SIEM index has events", total > 0, f"Total events: {total}")
    except Exception as e:
        check("SIEM index query", False, str(e))
        return

    # Check for specific event types from our attack tests
    try:
        r = requests.get(
            f"{os_base}/uni-auth-logs/_search",
            auth=(OS_USER, OS_PASS),
            json={
                "size": 0,
                "aggs": {"events": {"terms": {"field": "event", "size": 50}}}
            },
            verify=False,
            timeout=10
        )
        data = r.json()
        buckets = data.get("aggregations", {}).get("events", {}).get("buckets", [])
        event_types = {b["key"]: b["doc_count"] for b in buckets}
        print(f"    Event types in SIEM:")
        for evt, count in sorted(event_types.items(), key=lambda x: -x[1]):
            print(f"      {evt}: {count}")

        # Check for expected events from our attacks
        expected_events = {
            "login_failed": "Brute force attack logs",
            "ip_locked_login": "Login IP lockout alert",
            "access_denied": "Unauthorized access logs",
            "user_register_failed": "Failed registration logs",
            "ip_locked_registration": "Registration IP lockout alert",
            "password_reset_requested": "Password reset request logs",
            "login_success": "Successful login logs",
        }
        for evt, desc in expected_events.items():
            check(f"SIEM contains '{evt}' ({desc})",
                  evt in event_types,
                  f"Count: {event_types.get(evt, 0)}")

    except Exception as e:
        check("SIEM event aggregation", False, str(e))


# ===================================================================
#  TEST 8: AI ALERT TRIGGER CHECK
# ===================================================================
def test_ai_alert_trigger():
    header("TEST 8: AI ALERT TRIGGER CHECK")
    print("  Logging in as admin and triggering AI alert check...")
    print("  (This calls Ollama to analyze recent SIEM logs)")
    clear_ip_locks()

    s = requests.Session()
    r = s.post(f"{BASE}/login", data={
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD
    }, allow_redirects=False)

    if r.status_code != 302:
        check("Admin login for AI test", False, f"HTTP {r.status_code}")
        return

    # Follow redirect to set session
    s.get(f"{BASE}/admin/")

    # Call the AI alert check endpoint
    print("  Calling /admin/ai-alerts/check (may take ~30-60s for Ollama)...")
    try:
        r = s.get(f"{BASE}/admin/ai-alerts/check", timeout=180)
        data = r.json()
        check("AI alert check endpoint responds",
              data.get("ok") is True or data.get("ok") is False,
              f"Response: {json.dumps(data, indent=2)[:500]}")

        if data.get("ok"):
            if data.get("alert"):
                alert = data["alert"]
                check("AI detected suspicious activity",
                      True,
                      f"Title: {alert.get('title')}, Severity: {alert.get('severity')}")
                print(f"    AI Summary: {alert.get('summary', 'N/A')}")
            else:
                check("AI found no suspicious activity (may be expected if no recent attacks)",
                      True,
                      "No alert generated - attacks may not be in 10min window")
        else:
            error = data.get("error", "unknown")
            check("AI analysis returned ok=false", False, f"Error: {error}")

    except requests.exceptions.Timeout:
        check("AI alert check (timeout)", False, "Ollama took too long (>180s)")
    except Exception as e:
        check("AI alert check endpoint", False, str(e))


# ===================================================================
#  TEST 9: DoS ATTACK SIMULATION
# ===================================================================
def test_dos_attack():
    header("TEST 9: DoS ATTACK SIMULATION")
    print("  Config: warning=60 reqs/60s, block=120 reqs/60s")
    print("  Sending rapid requests to trigger warning then block...")

    s = requests.Session()
    blocked_seen = False
    block_at_request = None

    for i in range(1, 135):
        try:
            r = s.get(f"{BASE}/login", allow_redirects=False, timeout=5)
            if r.status_code == 429:
                if not blocked_seen:
                    blocked_seen = True
                    block_at_request = i
                    print(f"    Request {i}: HTTP 429 - BLOCKED!")
            elif i % 20 == 0:
                print(f"    Request {i}: HTTP {r.status_code} (normal)")
        except Exception as e:
            print(f"    Request {i}: ERROR - {e}")
            break

    check("DoS block triggered (HTTP 429 returned)",
          blocked_seen,
          f"Blocked at request #{block_at_request}" if blocked_seen else "Never blocked!")

    if blocked_seen:
        r = s.get(f"{BASE}/login", allow_redirects=False, timeout=5)
        still_blocked = r.status_code == 429
        check("DoS block persists on subsequent requests",
              still_blocked,
              f"Subsequent request: HTTP {r.status_code}")


# ===================================================================
#  TEST 10: DoS BLOCK RESPONSE CONTENT
# ===================================================================
def test_dos_block_response():
    header("TEST 10: DoS BLOCK RESPONSE CONTENT")

    s = requests.Session()
    # We should already be blocked from test 9, but send more to be sure
    print("  Sending requests to ensure DoS block is active...")

    blocked = False
    for i in range(1, 140):
        try:
            r = s.get(f"{BASE}/login", timeout=5)
            if r.status_code == 429:
                blocked = True
                has_429_title = "429 Too Many Requests" in r.text
                has_message = "temporarily blocked" in r.text
                check("429 response contains proper title",
                      has_429_title,
                      f"Has '429 Too Many Requests': {has_429_title}")
                check("429 response contains block message",
                      has_message,
                      f"Has 'temporarily blocked': {has_message}")

                # Verify ALL endpoints are blocked
                r2 = s.post(f"{BASE}/login", data={
                    "username": ADMIN_USERNAME,
                    "password": ADMIN_PASSWORD
                }, timeout=5)
                check("Login POST also blocked during DoS (429)",
                      r2.status_code == 429,
                      f"POST /login: HTTP {r2.status_code}")

                r3 = s.get(f"{BASE}/register", timeout=5)
                check("Register page also blocked during DoS (429)",
                      r3.status_code == 429,
                      f"GET /register: HTTP {r3.status_code}")

                r4 = s.post(f"{BASE}/forgot-password", data={"email": "a@b.com"}, timeout=5)
                check("Password reset also blocked during DoS (429)",
                      r4.status_code == 429,
                      f"POST /forgot-password: HTTP {r4.status_code}")
                break
        except Exception:
            pass

    if not blocked:
        check("DoS block was triggered", False, "Never got 429 after 140 requests")


# ===================================================================
#  MAIN
# ===================================================================
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print("\n" + "="*70)
    print("  UNIVERSITY PORTAL SIEM - ATTACK SIMULATION TEST SUITE")
    print("="*70)
    print(f"  Target: {BASE}")
    print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Verify app is up
    try:
        r = requests.get(f"{BASE}/login", timeout=5)
        print(f"  App Status: UP (HTTP {r.status_code})")
    except Exception:
        print("  App Status: DOWN - Cannot proceed!")
        sys.exit(1)

    # ---- Non-DoS tests first ----
    test_brute_force_login()

    clear_ip_locks()
    test_mass_registration()

    clear_ip_locks()
    test_password_reset_abuse()

    clear_ip_locks()
    test_unauthorized_access()

    clear_ip_locks()
    test_captcha_validation()

    clear_ip_locks()
    test_login_after_lock_clear()

    # SIEM verification (needs OpenSearch)
    test_siem_logging()

    # AI Alert check (needs Ollama + OpenSearch)
    clear_ip_locks()
    test_ai_alert_trigger()

    # ---- DoS tests LAST (they block 127.0.0.1 in-memory) ----
    print("\n" + "="*70)
    print("  NOTE: DoS tests run last - they will block this IP in-memory")
    print("="*70)
    clear_ip_locks()
    test_dos_attack()
    test_dos_block_response()

    # ---- Summary ----
    header("TEST RESULTS SUMMARY")
    total = passed + failed
    print(f"  Total:  {total}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    if warnings_list:
        print(f"\n  Warnings:")
        for w in warnings_list:
            print(f"    - {w}")
    print()

    if failed > 0:
        print("  STATUS: SOME TESTS FAILED")
    else:
        print("  STATUS: ALL TESTS PASSED")
    print()
