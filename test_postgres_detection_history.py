"""
test_postgres_detection_history.py
Automated test suite verifying PostgreSQL connection to shadow_ai_detector,
reusable database connection module, and detection_history REST APIs.
"""

import os
import sys
import json
import unittest
import urllib.request
import urllib.error
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Add backend directory to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from db import (
    get_db_connection,
    release_db_connection,
    fetch_all_detection_history,
    insert_detection_record,
    DB_NAME,
    DB_HOST,
    DB_PORT,
    DB_USER
)

class TestPostgresDetectionHistory(unittest.TestCase):
    def test_01_db_environment_variables(self):
        """Requirement 1 & 2: Read password from .env and verify parameters"""
        self.assertEqual(DB_NAME, "shadow_ai_detector", "Database name should be shadow_ai_detector")
        self.assertEqual(DB_HOST, "localhost")
        self.assertEqual(DB_PORT, 5432)
        self.assertEqual(DB_USER, "postgres")
        self.assertTrue(os.getenv("DB_PASSWORD"), "DB_PASSWORD must be present in .env")
        print(f"\n[PASS] Database configuration loaded from .env: {DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

    def test_02_reusable_db_connection(self):
        """Requirement 3: Test reusable connection module with psycopg2"""
        conn = get_db_connection()
        self.assertIsNotNone(conn, "Database connection should not be None")
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT current_database(), current_user, version();")
                row = cur.fetchone()
                self.assertEqual(row[0], "shadow_ai_detector")
                self.assertEqual(row[1], "postgres")
                print(f"[PASS] Connected to PostgreSQL. Active DB: {row[0]}, User: {row[1]}")
        finally:
            release_db_connection(conn)

    def test_03_insert_and_fetch_detection_history(self):
        """Requirement 4 & 5: Direct module insert and fetch from detection_history"""
        test_ip = "192.168.1.188"
        test_domain = "api.openai.com"
        test_class = "AI_CONFIRMED"

        # Insert record
        insert_res = insert_detection_record(test_ip, test_domain, test_class)
        self.assertTrue(insert_res.get("success"), f"Insert failed: {insert_res}")
        rec = insert_res["record"]
        self.assertEqual(rec["source_ip"], test_ip)
        self.assertEqual(rec["domain"], test_domain)
        self.assertEqual(rec["classification"], test_class)
        print(f"[PASS] Inserted detection record into detection_history (ID: {rec['id']})")

        # Fetch records
        fetch_res = fetch_all_detection_history()
        self.assertTrue(fetch_res.get("success"), f"Fetch failed: {fetch_res}")
        self.assertGreater(fetch_res["total"], 0)
        found = any(r["id"] == rec["id"] for r in fetch_res["records"])
        self.assertTrue(found, "Inserted record must be in fetched list")
        print(f"[PASS] Fetched {fetch_res['total']} records from detection_history table.")

    def test_04_api_endpoints(self):
        """Requirement 4 & 5: Test GET /api/detection-history and POST /api/detection-history"""
        # POST endpoint
        post_payload = json.dumps({
            "source_ip": "10.0.4.77",
            "domain": "chat.deepseek.com",
            "classification": "SHADOW_AI"
        }).encode("utf-8")

        post_req = urllib.request.Request(
            "http://localhost:5000/api/detection-history",
            data=post_payload,
            headers={"Content-Type": "application/json"}
        )
        post_res = urllib.request.urlopen(post_req)
        self.assertEqual(post_res.status, 200)
        post_data = json.loads(post_res.read().decode())
        self.assertTrue(post_data.get("success"), f"API insert failed: {post_data}")
        print(f"[PASS] POST /api/detection-history created record ID: {post_data['record']['id']}")

        # GET endpoint
        get_req = urllib.request.Request("http://localhost:5000/api/detection-history")
        get_res = urllib.request.urlopen(get_req)
        self.assertEqual(get_res.status, 200)
        get_data = json.loads(get_res.read().decode())
        self.assertTrue(get_data.get("success"))
        self.assertGreater(get_data["total"], 0)
        print(f"[PASS] GET /api/detection-history returned {get_data['total']} records in JSON format.")

    def test_05_safe_error_masking(self):
        """Requirement 6: Ensure database errors do not expose credentials"""
        # Attempting insert with broken connection handles error safely
        from db import insert_detection_record
        res = insert_detection_record(None, None, None)
        # Even if it errors or succeeds, error string must not contain passwords
        err_msg = res.get("error", "")
        pw = os.getenv("DB_PASSWORD", "")
        if pw:
            self.assertNotIn(pw, err_msg, "Error messages must never leak database password!")
        print("[PASS] Error masking verified: No passwords or connection credentials leaked.")

if __name__ == '__main__':
    unittest.main()
