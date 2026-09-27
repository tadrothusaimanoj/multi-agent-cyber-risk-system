import sqlite3
conn = sqlite3.connect('cyberguard.db')
cur = conn.cursor()
cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='findings'")
print(cur.fetchall()[0][0])
