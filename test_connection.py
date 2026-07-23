import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
print("DATABASE_URL is:", DATABASE_URL)

conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor()
cursor.execute("SELECT * FROM fridges;")
rows = cursor.fetchall()
print("Fridges in database:", rows)

cursor.close()
conn.close()