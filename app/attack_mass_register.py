"""
Mass Registration (Bot) Attack Simulation Script
================================================
This script simulates an automated bot attempting to flood the system
with fake student registrations.

Expected outcome:
1. The script will fail to bypass the CAPTCHA mechanism.
2. Even if it guessed the CAPTCHA, the IP Rate Limiter will block the IP
   after 5 registration attempts in a 2-minute window.
"""

import requests
import time
import random
import string
import re

TARGET_URL = "http://127.0.0.1:5000/register"
ATTEMPTS = 8
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def get_csrf_token(session):
    response = session.get(TARGET_URL, timeout=5)
    match = CSRF_RE.search(response.text)
    if not match:
        raise RuntimeError(f"CSRF token not found (HTTP {response.status_code})")
    return match.group(1)

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

print("=" * 50)
print(f"🤖 Initiating Mass Registration Bot Attack on {TARGET_URL}")
print(f"🔢 Bots Planned: {ATTEMPTS}")
print("=" * 50)
print("Waiting 2 seconds before starting...\n")
time.sleep(2)

session = requests.Session()

for i in range(1, ATTEMPTS + 1):
    bot_username = f"bot_{generate_random_string(5)}"
    bot_email = f"{bot_username}@evil-domain.com"
    bot_password = "EvilPassword123!"
    
    # We send a random number for the CAPTCHA answer
    fake_captcha = str(random.randint(1, 20))
    
    payload = {
        "username": bot_username,
        "email": bot_email,
        "password": bot_password,
        "role": "student",
        "captcha_answer": fake_captcha,
        "csrf_token": get_csrf_token(session)
    }
    
    print(f"[{i}/{ATTEMPTS}] Registering '{bot_username}' (Guessing CAPTCHA: {fake_captcha}) ... ", end="", flush=True)
    
    try:
        response = session.post(TARGET_URL, data=payload)
        html_content = response.text.lower()
        
        if "too many registration attempts" in html_content:
            print("🛑 BLOCKED (IP Registration Lockout Triggered!)")
        elif "incorrect captcha answer" in html_content:
            print("❌ Failed (CAPTCHA Defense worked)")
        elif "please verify your email" in html_content:
            print("⚠️ Success (Account created, pending email)")
        else:
            print(f"⚠️ Unknown response (HTTP {response.status_code})")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Connection error: {e}")
        
    time.sleep(0.5)

print("\n" + "=" * 50)
print("🏁 Mass Registration Simulation Complete")
print("💡 Check the Admin Dashboard to see 'user_register_failed' events.")
print("   The AI should flag this behavior as a Mass Registration attempt.")
print("=" * 50)
