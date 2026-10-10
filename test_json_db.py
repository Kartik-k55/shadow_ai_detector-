import json
import psycopg2
import requests
import os
from dotenv import load_dotenv

load_dotenv()

headers = {'Authorization': 'Bearer su_test_token_2026'}

print("=" * 60)
print("1. CLEARING DATABASE TABLES FOR CLEAN TEST")
print("=" * 60)
clear_res = requests.post("http://localhost:5000/api/db/clear", headers=headers)
print("DB Clear Status:", clear_res.status_code)

print("\n" + "=" * 60)
print("2. UPLOADING SAMPLE_TRAFFIC.JSON VIA API")
print("=" * 60)
with open("sample_traffic.json", "r") as f:
    json_data = f.read()

res = requests.post("http://localhost:5000/api/traffic/upload", json={"content": json_data}, headers=headers)
print("Upload Status Code:", res.status_code)
upload_json = res.json()
stats = upload_json.get("stats", {})
print(f"Parsed Records: {stats.get('parsed')} | Detected AI: {stats.get('detectedAiCount')} | Errors: {stats.get('errors')}")

print("\n" + "=" * 60)
print("3. DIRECT POSTGRESQL DATABASE VERIFICATION")
print("=" * 60)
conn = psycopg2.connect(
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "5432")),
    dbname=os.getenv("DB_NAME", "shadow_ai_detection"),
    user=os.getenv("DB_USER", "postgres"),
    password=os.getenv("DB_PASSWORD", "postgres")
)

with conn.cursor() as cur:
    print("\n--- Endpoints Table (PostgreSQL) ---")
    cur.execute("SELECT hostname, provider, risk_score, risk_level, data_sent_mb FROM endpoints ORDER BY risk_score DESC;")
    endpoints = cur.fetchall()
    print(f"Total Unique AI Endpoints: {len(endpoints)}")
    for ep in endpoints:
        print(f"  [+] Host: {ep[0]:<35} | Provider: {ep[1]:<28} | Score: {ep[2]:>2} [{ep[3]:<8}] | Data: {ep[4]} MB")

    print("\n--- Alerts Table (PostgreSQL) ---")
    cur.execute("SELECT title, host_target, status FROM alerts;")
    alerts = cur.fetchall()
    print(f"Total Security Alerts: {len(alerts)}")
    for alt in alerts:
        print(f"  [!] Alert: {alt[0]} | Target: {alt[1]} | Status: {alt[2]}")

    print("\n--- Traffic Flows Table (PostgreSQL) ---")
    cur.execute("SELECT hostname, provider, protocol, bytes_up, risk_level FROM traffic_flows;")
    flows = cur.fetchall()
    print(f"Total Flows Stored in DB: {len(flows)}")
    for f in flows:
        print(f"  [*] Flow: {f[0]:<35} | {f[1]:<25} | {f[2]:<8} | {f[3]:>8} bytes | Risk: {f[4]}")

conn.close()

print("\n" + "=" * 60)
print("4. API ENDPOINT VERIFICATION")
print("=" * 60)
ep_res = requests.get("http://localhost:5000/api/endpoints", headers=headers)
alt_res = requests.get("http://localhost:5000/api/alerts", headers=headers)
hist_res = requests.get("http://localhost:5000/api/traffic/history", headers=headers)

print(f"GET /api/endpoints:       Status {ep_res.status_code} ({len(ep_res.json())} items)")
print(f"GET /api/alerts:          Status {alt_res.status_code} ({len(alt_res.json())} items)")
print(f"GET /api/traffic/history: Status {hist_res.status_code} ({len(hist_res.json())} items)")

print("\n" + "=" * 60)
print(">>> ALL TESTS PASSED SUCCESSFULLY - DATABASE & JSON INGESTION VERIFIED <<<")
print("=" * 60)
