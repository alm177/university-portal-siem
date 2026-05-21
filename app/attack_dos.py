"""
DoS (Denial of Service) Attack Simulation Script
==============================================
This script simulates a Layer 7 HTTP flood attack against the University Portal.
It is designed to trigger the application's in-memory sliding window DoS protection.

Expected outcome:
1. The server will accept the first 60 requests and log a SIEM warning.
2. The server will accept requests 61-119.
3. Upon reaching 120 requests within 60 seconds, the IP will be blocked.
4. Subsequent requests will return HTTP 429 Too Many Requests.
"""

import requests
import time
import threading

# Configuration
TARGET_URL = "http://127.0.0.1:5000/login"
TOTAL_REQUESTS = 150
CONCURRENT_THREADS = 10

print("=" * 50)
print(f"🚀 Initiating DoS Attack on {TARGET_URL}")
print(f"📦 Total Requests: {TOTAL_REQUESTS} | Threads: {CONCURRENT_THREADS}")
print("=" * 50)
print("Waiting 2 seconds before starting...\n")
time.sleep(2)

def make_request(thread_id, requests_per_thread):
    for i in range(requests_per_thread):
        try:
            # We use a GET request to the login page as it's typically a public, cache-busting endpoint
            response = requests.get(TARGET_URL, timeout=5)
            status = response.status_code
            
            if status == 429:
                print(f"[Thread {thread_id}] Request {i+1}: 🛑 HTTP 429 - BLOCKED BY DoS PROTECTION!")
                break # Stop this thread once blocked
            else:
                print(f"[Thread {thread_id}] Request {i+1}: ✅ HTTP {status} - Allowed")
                
        except requests.exceptions.RequestException as e:
            print(f"[Thread {thread_id}] Request {i+1}: ❌ Error connecting: {e}")
            break

# Calculate requests per thread
requests_per_thread = TOTAL_REQUESTS // CONCURRENT_THREADS

threads = []
start_time = time.time()

# Launch threads
for i in range(CONCURRENT_THREADS):
    t = threading.Thread(target=make_request, args=(i, requests_per_thread))
    threads.append(t)
    t.start()

# Wait for all threads to complete
for t in threads:
    t.join()

end_time = time.time()
duration = end_time - start_time

print("\n" + "=" * 50)
print("🏁 DoS Attack Simulation Complete")
print(f"⏱️  Duration: {duration:.2f} seconds")
print("💡 Check the Admin Dashboard to see the DoS events and IP block!")
print("=" * 50)
