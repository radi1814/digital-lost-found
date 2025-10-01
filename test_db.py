from database import get_db_connection

conn = get_db_connection()
cur = conn.cursor()

cur.execute(
    "SELECT table_name FROM information_schema.tables WHERE table_schema='public';")
tables = cur.fetchall()

print("Tables in database:", tables)

cur.close()
conn.close()
