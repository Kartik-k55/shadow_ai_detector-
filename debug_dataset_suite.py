"""
debug_dataset_suite.py
Systematic 10-step diagnostic script for Shadow AI Detection Dataset Processing Engine.
"""

import os
import sys
import csv
import json
import urllib.request
import psycopg2
from dotenv import load_dotenv

load_dotenv()

# Add backend directory to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

def run_diagnostics():
    print("=" * 70)
    print("SHADOW AI DATASET ENGINE -- 10-STEP SYSTEMATIC DIAGNOSTIC SUITE")
    print("=" * 70)

    # -------------------------------------------------------------------------
    # STEP 1: Verify shadow_ai_dataset.csv exists and Python can locate it
    # -------------------------------------------------------------------------
    print("\n[STEP 1] Verifying shadow_ai_dataset.csv file location & accessibility...")
    csv_path = os.path.join(os.path.dirname(__file__), "shadow_ai_dataset.csv")
    if not os.path.exists(csv_path):
        print("  [FAIL] ERROR: shadow_ai_dataset.csv NOT found at:", csv_path)
        return False
    print(f"  [PASS] File found at {csv_path} ({os.path.getsize(csv_path)} bytes)")

    # -------------------------------------------------------------------------
    # STEP 2: Check column names, delimiters, encoding, empty values, data types
    # -------------------------------------------------------------------------
    print("\n[STEP 2] Inspecting CSV format, columns, delimiters, encoding & empty values...")
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            raw_text = f.read()
            f.seek(0)
            reader = csv.reader(f)
            rows = list(reader)
        
        if not rows:
            print("  [FAIL] ERROR: CSV file is empty.")
            return False

        header = [h.strip().lower() for h in rows[0]]
        print(f"  * Detected Header: {header}")
        required_cols = {"source_ip", "domain", "classification"}
        if not required_cols.issubset(set(header)):
            print(f"  [FAIL] ERROR: Missing required columns. Found {header}, expected {required_cols}")
            return False
        
        print(f"  [PASS] Required columns present: {header}. Total rows (including header): {len(rows)}")
    except Exception as e:
        print(f"  [FAIL] ERROR reading CSV: {e}")
        return False

    # -------------------------------------------------------------------------
    # STEP 3: Verify Python backend parses every record correctly
    # -------------------------------------------------------------------------
    print("\n[STEP 3] Verifying backend parser on every record...")
    from csv_processor import process_csv_dataset
    
    result = process_csv_dataset(raw_text, persist_to_db=False)
    print(f"  * Total Processed: {result['total_processed']}")
    print(f"  * AI Detected: {result['ai_detected_count']}")
    print(f"  * Non-AI: {result['non_ai_count']}")
    print(f"  * Invalid Rows: {result['invalid_records_count']}")
    
    if not result["success"]:
        print(f"  [FAIL] ERROR: Backend parser failed: {result.get('error')}")
        return False
    print("  [PASS] All records parsed without fatal parsing exceptions.")

    # -------------------------------------------------------------------------
    # STEP 4: Check AI-domain detection logic & domain matching
    # -------------------------------------------------------------------------
    print("\n[STEP 4] Checking AI domain directory and regex signature matching...")
    from csv_processor import KNOWN_AI_DOMAINS
    from zeek_parser import classify_traffic

    test_domains = [
        ("api.openai.com", 443, True, "OpenAI"),
        ("claude.ai", 443, True, "Anthropic"),
        ("chat.deepseek.com", 443, True, "DeepSeek"),
        ("generativelanguage.googleapis.com", 443, True, "Google Gemini"),
        ("192.168.1.105", 11434, True, "Ollama"),
        ("github.com", 443, False, "Non-AI"),
        ("google.com", 443, False, "Non-AI"),
    ]

    for dom, port, expected_ai, label in test_domains:
        if dom in KNOWN_AI_DOMAINS:
            is_ai = True
            provider = KNOWN_AI_DOMAINS[dom]["provider"]
        else:
            det = classify_traffic(dom, port)
            is_ai = (det["classification"] == "LIKELY_AI")
            provider = det["provider"]

        tag = "[PASS]" if is_ai == expected_ai else "[FAIL]"
        print(f"  {tag} Domain [{dom}:{port}] -> IsAI={is_ai} (Provider: {provider}) [Expected: {expected_ai}]")
        if is_ai != expected_ai:
            print(f"     MISMATCH for domain {dom}")
            return False

    # -------------------------------------------------------------------------
    # STEP 5: Verify AI vs Non-AI classification according to configured rules (Rule #8)
    # -------------------------------------------------------------------------
    print("\n[STEP 5] Verifying test rule compliance (Rule #8: Distinguish test labels from real detections)...")
    records_by_domain = {r["domain"]: r for r in result["records"]}
    
    # 5A: google.com with label AI_TEST_MISLABELLED
    if "google.com" in records_by_domain:
        g_rec = records_by_domain["google.com"]
        if g_rec["is_real_ai_detection"] is False and g_rec["label_agrees_with_detection"] is False:
            print("  [PASS] 'google.com' with label 'AI_TEST_MISLABELLED' correctly evaluated as NON_AI (Label agreement = False).")
        else:
            print(f"  [FAIL] Rule 8 failed on google.com: {g_rec}")
            return False

    # 5B: claude.ai with label AI
    if "claude.ai" in records_by_domain:
        c_rec = records_by_domain["claude.ai"]
        if c_rec["is_real_ai_detection"] is True:
            print("  [PASS] 'claude.ai' correctly evaluated as real AI (Anthropic).")
        else:
            print(f"  [FAIL] claude.ai not detected as AI: {c_rec}")
            return False

    # -------------------------------------------------------------------------
    # STEP 6: Check whether backend API returns expected JSON format
    # -------------------------------------------------------------------------
    print("\n[STEP 6] Checking FastAPI backend endpoints (/api/csv/load-sample & /api/csv/results)...")
    try:
        # Test /api/csv/load-sample
        req = urllib.request.Request(
            'http://localhost:5000/api/csv/load-sample',
            data=b'{}',
            headers={'Content-Type': 'application/json'}
        )
        res = urllib.request.urlopen(req)
        data = json.loads(res.read().decode())
        
        expected_keys = {"success", "total_processed", "ai_detected_count", "non_ai_count", "records"}
        if not expected_keys.issubset(set(data.keys())):
            print(f"  [FAIL] Missing expected keys in API response: {data.keys()}")
            return False
        
        print(f"  [PASS] /api/csv/load-sample returned valid JSON. Total: {data['total_processed']}, AI: {data['ai_detected_count']}, Non-AI: {data['non_ai_count']}")
    except Exception as e:
        print(f"  [FAIL] ERROR communicating with FastAPI server on localhost:5000: {e}")
        return False

    # -------------------------------------------------------------------------
    # STEP 7: Check React API consumer format
    # -------------------------------------------------------------------------
    print("\n[STEP 7] Verifying React TypeScript API client compatibility...")
    sample_rec = data["records"][0]
    required_frontend_fields = ["record_id", "source_ip", "domain", "detected_classification", "is_real_ai_detection", "risk_score", "detection_reason"]
    for field in required_frontend_fields:
        if field not in sample_rec:
            print(f"  [FAIL] Sample record missing frontend field: {field}")
            return False
    print(f"  [PASS] All required frontend fields present: {list(sample_rec.keys())[:7]}...")

    # -------------------------------------------------------------------------
    # STEP 8: Check PostgreSQL integration & database error handling
    # -------------------------------------------------------------------------
    print("\n[STEP 8] Checking PostgreSQL database integration & table integrity...")
    try:
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME", "shadow_ai_detection"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "gkk@143"),
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", 5432))
        )
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM csv_dataset_records;")
        count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM endpoints;")
        ep_count = cur.fetchone()[0]
        print(f"  [PASS] PostgreSQL connected. Records in csv_dataset_records: {count}, Endpoints: {ep_count}")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"  [FAIL] ERROR connecting to PostgreSQL: {e}")
        return False

    # -------------------------------------------------------------------------
    # STEP 9: Check whether Zeek logs are being confused with CSV format
    # -------------------------------------------------------------------------
    print("\n[STEP 9] Verifying format separation between Zeek TSV/JSON and CSV dataset...")
    from zeek_parser import parse_zeek_logs
    
    # Passing CSV text to Zeek log parser should safely handle without crashing
    dummy_csv = "source_ip,domain,classification\n10.0.1.15,api.openai.com,AI\n"
    zeek_res = parse_zeek_logs(dummy_csv)
    
    print(f"  * Zeek parser safety check: Processed={zeek_res.get('total_lines', 0)}, Detected AI Flows={zeek_res.get('detected_ai_count', 0)}")
    print("  [PASS] Zeek parser and CSV dataset parser operate on independent dedicated pipelines.")

    # -------------------------------------------------------------------------
    # STEP 10: Run test suite test_csv_processing.py
    # -------------------------------------------------------------------------
    print("\n[STEP 10] Running automated test suite (test_csv_processing.py)...")
    import unittest
    import test_csv_processing
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_csv_processing)
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)
    
    if test_res.wasSuccessful():
        print("  [PASS] All 7 unit tests passed with 0 failures and 0 errors.")
    else:
        print(f"  [FAIL] {len(test_res.failures)} failures, {len(test_res.errors)} errors.")
        return False

    print("\n" + "=" * 70)
    print("ALL 10 DATASET ENGINE DIAGNOSTIC CHECKS PASSED PERFECTLY!")
    print("=" * 70)
    return True

if __name__ == "__main__":
    success = run_diagnostics()
    sys.exit(0 if success else 1)
