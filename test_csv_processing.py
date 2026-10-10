"""
test_csv_processing.py
Automated test suite for Shadow AI Detection CSV Dataset Processing Engine.
Validates:
1. Missing columns detection
2. Invalid IP address rejection
3. Empty / malformed domain rejection
4. Unsupported / test classification handling
5. Configurable AI domain identification (OpenAI, Anthropic, Gemini, Ollama, DeepSeek, etc.)
6. Rule #8 compliance: Distinguishing test labels from actual detection results (e.g. mislabeled rows)
7. PostgreSQL persistence and querying of csv_dataset_records
"""

import os
import sys
import unittest
import psycopg2
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Add backend directory to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from csv_processor import (
    validate_ip_address,
    validate_domain,
    process_csv_dataset,
    load_and_process_sample_dataset,
    KNOWN_AI_DOMAINS
)

class TestCsvValidation(unittest.TestCase):
    def test_ip_validation(self):
        self.assertTrue(validate_ip_address("192.168.1.100")[0])
        self.assertTrue(validate_ip_address("10.0.0.1")[0])
        self.assertTrue(validate_ip_address("127.0.0.1:11434")[0]) # Port handling
        self.assertFalse(validate_ip_address("999.999.999.999")[0])
        self.assertFalse(validate_ip_address("not_an_ip")[0])
        self.assertFalse(validate_ip_address("")[0])

    def test_domain_validation(self):
        self.assertTrue(validate_domain("api.openai.com")[0])
        self.assertTrue(validate_domain("claude.ai")[0])
        valid, host, port = validate_domain("localhost:11434")
        self.assertTrue(valid)
        self.assertEqual(port, 11434)
        self.assertFalse(validate_domain("")[0])
        self.assertFalse(validate_domain("   ")[0])
        self.assertFalse(validate_domain("invalid domain with spaces")[0])

    def test_rule_8_distinguish_test_label_from_actual_detection(self):
        """
        Requirement 8: Do not treat every record labelled AI as a real detection.
        Distinguish test labels from actual detection results.
        """
        # Test Case 1: Mislabeled non-AI domain with "AI_TEST_MISLABELLED" label
        test_csv = (
            "source_ip,domain,classification\n"
            "192.168.1.50,google.com,AI_TEST_MISLABELLED\n"
            "192.168.1.51,api.anthropic.com,AI\n"
            "192.168.1.52,github.com,NON_AI\n"
            "192.168.1.53,127.0.0.1:11434,AI\n"
        )
        res = process_csv_dataset(test_csv, persist_to_db=False)
        self.assertEqual(res["total_processed"], 4)
        
        recs = {r["domain"]: r for r in res["records"]}
        
        # google.com should NOT be treated as real AI even if labeled AI_TEST_MISLABELLED
        google_rec = recs["google.com"]
        self.assertFalse(google_rec["is_real_ai_detection"])
        self.assertEqual(google_rec["detected_classification"], "NON_AI")
        self.assertFalse(google_rec["label_agrees_with_detection"])

        # api.anthropic.com is real AI
        claude_rec = recs["api.anthropic.com"]
        self.assertTrue(claude_rec["is_real_ai_detection"])
        self.assertEqual(claude_rec["detected_classification"], "LIKELY_AI")
        self.assertIn("Anthropic", claude_rec["provider"])

        # 127.0.0.1:11434 (Ollama) is detected as real local AI
        ollama_rec = recs["127.0.0.1"]
        self.assertTrue(ollama_rec["is_real_ai_detection"])
        self.assertIn("Ollama", ollama_rec["provider"])

    def test_missing_columns_validation(self):
        invalid_csv = "source_ip,wrong_column\n192.168.1.1,foo\n"
        result = process_csv_dataset(invalid_csv, persist_to_db=False)
        self.assertFalse(result["success"])
        self.assertIn("Missing required CSV column", result["error"])

    def test_invalid_records_handling(self):
        mixed_csv = (
            "source_ip,domain,classification\n"
            "invalid_ip,api.openai.com,AI\n"
            "192.168.1.1,,AI\n"
            "192.168.1.3,api.openai.com,AI\n"
        )
        result = process_csv_dataset(mixed_csv, persist_to_db=False)
        self.assertEqual(result["total_processed"], 3)
        self.assertEqual(result["invalid_records_count"], 2)
        self.assertEqual(result["ai_detected_count"], 1)

    def test_sample_dataset_file(self):
        sample_path = os.path.join(os.path.dirname(__file__), 'shadow_ai_dataset.csv')
        self.assertTrue(os.path.exists(sample_path), "shadow_ai_dataset.csv must exist")
        
        result = load_and_process_sample_dataset(sample_path)
        self.assertTrue(result["success"])
        self.assertGreater(result["total_processed"], 10)
        self.assertGreater(result["ai_detected_count"], 5)
        self.assertGreater(result["non_ai_count"], 3)
        print(f"\n[OK] Sample CSV Processed: {result['total_processed']} total, {result['ai_detected_count']} AI, {result['non_ai_count']} Non-AI, {result['invalid_records_count']} invalid.")

    def test_postgresql_persistence(self):
        """Test that records are correctly saved and retrieved from PostgreSQL"""
        from db import init_db_pool
        init_db_pool()

        # Insert a sample batch to verify persistence
        sample_path = os.path.join(os.path.dirname(__file__), 'shadow_ai_dataset.csv')
        load_and_process_sample_dataset(sample_path)

        db_name = os.getenv("DB_NAME", "shadow_ai_detection")
        db_user = os.getenv("DB_USER", "postgres")
        db_password = os.getenv("DB_PASSWORD", "gkk@143")
        db_host = os.getenv("DB_HOST", "localhost")
        db_port = int(os.getenv("DB_PORT", 5432))

        try:
            conn = psycopg2.connect(
                dbname=db_name,
                user=db_user,
                password=db_password,
                host=db_host,
                port=db_port
            )
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM csv_dataset_records;")
            count = cur.fetchone()[0]
            self.assertGreater(count, 0)
            print(f"[OK] PostgreSQL csv_dataset_records table verified. Current row count: {count}")
            
            # Fetch 3 recent rows to verify schema and data
            cur.execute("SELECT source_ip, domain, detected_classification, is_real_ai_detection, provider, risk_score FROM csv_dataset_records LIMIT 3;")
            rows = cur.fetchall()
            print(f"[OK] Sample persisted rows from PostgreSQL:")
            for r in rows:
                print(f"     IP: {r[0]}, Domain: {r[1]}, Classification: {r[2]}, IsAI: {r[3]}, Provider: {r[4]}, Risk: {r[5]}")
            
            cur.close()
            conn.close()
        except Exception as e:
            self.fail(f"PostgreSQL connection/query failed: {e}")

if __name__ == '__main__':
    unittest.main()
