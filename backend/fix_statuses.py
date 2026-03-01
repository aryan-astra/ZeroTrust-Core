"""Quick fix script to clean up stale TRUSTED statuses in the database."""
import pymysql

conn = pymysql.connect(host='localhost', port=3306, user='root', password='password', database='zerotrust')
cur = conn.cursor()

cur.execute("UPDATE devices SET status='SAFE' WHERE status='TRUSTED'")
u1 = cur.rowcount

cur.execute("UPDATE activity_log SET status='SAFE' WHERE status='TRUSTED'")
u2 = cur.rowcount

conn.commit()
print(f"Fixed {u1} devices, {u2} activities from TRUSTED -> SAFE")

cur.execute("SELECT status, COUNT(id) FROM devices GROUP BY status")
print("Device statuses:", dict(cur.fetchall()))

cur.execute("SELECT COUNT(id) FROM risk_events")
print("Risk events:", cur.fetchone()[0])

conn.close()
