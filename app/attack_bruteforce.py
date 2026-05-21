"""
Brute Force Attack Simulation Script
====================================
This script simulates a T1110 Brute Force attack by attempting to guess 
a user's password rapidly.

Expected outcome:
1. The first 5 requests will fail (HTTP 200 with error message in HTML).
2. The 6th request will trigger the IP Lockout mechanism in SQLite.
3. Subsequent requests will show "Too many failed login attempts" and bypass the hashing engine.
"""

import requests
import time
import re

TARGET_URL = "http://127.0.0.1:5000/login"
TARGET_USER = "admin"
ATTEMPTS = 8
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def get_csrf_token(session):
    response = session.get(TARGET_URL, timeout=5)
    match = CSRF_RE.search(response.text)
    if not match:
        raise RuntimeError(f"CSRF token not found (HTTP {response.status_code})")
    return match.group(1)

print("=" * 50)
print(f"🔨 Initiating Brute Force Attack on {TARGET_URL}")
print(f"🎯 Target Account: '{TARGET_USER}'")
print(f"🔢 Attempts Planned: {ATTEMPTS}")
print("=" * 50)
print("Waiting 2 seconds before starting...\n")
time.sleep(2)

session = requests.Session()

for i in range(1, ATTEMPTS + 1):
    password_guess = f"Password123!_{i}"
    
    payload = {
        "username": TARGET_USER,
        "password": password_guess,
        "csrf_token": get_csrf_token(session)
    }
    
    print(f"[{i}/{ATTEMPTS}] Trying password: '{password_guess}' ... ", end="", flush=True)
    
    try:
        response = session.post(TARGET_URL, data=payload)
        html_content = response.text.lower()
        
        if "too many failed login attempts" in html_content:
            print("🛑 BLOCKED (IP Lockout Triggered!)")
        elif "username or password is wrong" in html_content:
            print("❌ Failed (Wrong Password)")
        else:
            print(f"⚠️ Unknown response (HTTP {response.status_code})")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Connection error: {e}")
        
    time.sleep(0.5) # Slight delay to simulate a script

print("\n" + "=" * 50)
print("🏁 Brute Force Simulation Complete")
print("💡 Check the Admin Dashboard for 'failed_login' and 'ip_locked' events!")
print("=" * 50)
