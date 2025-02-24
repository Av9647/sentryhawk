import sqlite3

conn = sqlite3.connect("cyber_threats.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM staging_cve LIMIT 5;")
results = cursor.fetchall()

for row in results:
    print(row)

conn.close()