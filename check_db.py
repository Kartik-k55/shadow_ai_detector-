import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

try:
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=int(os.getenv('DB_PORT', '5432')),
        dbname=os.getenv('DB_NAME', 'shadow_ai_detection'),
        user=os.getenv('DB_USER', 'postgres'),
        password=os.getenv('DB_PASSWORD', 'postgres')
    )
    cur = conn.cursor()
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
    tables = [r[0] for r in cur.fetchall()]
    print(f"DATABASE STATUS: OK - Connected to {os.getenv('DB_NAME')} on {os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}")
    print(f"Total Tables in PostgreSQL: {len(tables)}")
    for t in sorted(tables):
        cur.execute(f"SELECT COUNT(*) FROM {t};")
        cnt = cur.fetchone()[0]
        print(f"  - {t:<25}: {cnt} rows")
    conn.close()
except Exception as e:
    print("DATABASE ERROR:", e)
