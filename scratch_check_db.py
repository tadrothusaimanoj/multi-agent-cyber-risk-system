import sqlite3

conn = sqlite3.connect('cyberguard.db')
cur = conn.cursor()
cur.execute("SELECT id, finding_id, title FROM findings WHERE finding_id='FIND-2024-001'")
rows = cur.fetchall()
for r in rows:
    print(r)
