import os, pymysql

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
MYSQL_HOST = os.getenv("MYSQL_HOST")
MYSQL_PORT = int(os.getenv("MYSQL_PORT"))
MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASS = os.getenv("MYSQL_PASS")
MYSQL_DB   = os.getenv("MYSQL_DB")
def connect():
    return pymysql.connect(host=MYSQL_HOST, port=MYSQL_PORT, user=MYSQL_USER,
                           password=MYSQL_PASS, db=MYSQL_DB, autocommit=True)

def ensure_schema():
    db = connect()
    cur = db.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      username VARCHAR(100) NOT NULL,
      salt VARBINARY(32) NOT NULL,
      pwd_hash CHAR(64) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    cur.close()
    db.close()

def insert_user(email, username, salt_bytes, pwd_hash_hex):
    db = connect()
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                    (email, username, salt_bytes, pwd_hash_hex))
        return True
    except Exception:
        return False
    finally:
        cur.close()
        db.close()

def get_user_by_email(email):
    db = connect()
    cur = db.cursor()
    cur.execute("SELECT id,email,username,salt,pwd_hash FROM users WHERE email=%s", (email,))
    row = cur.fetchone()
    cur.close()
    db.close()
    if not row:
        return None
    return {"id":row[0], "email":row[1], "username":row[2], "salt":row[3], "pwd_hash":row[4]}
