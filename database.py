import os
import sqlite3
from PyQt5.QtWidgets import QMessageBox


# Create the main users database
def create_db():
    conn = sqlite3.connect('users.db')
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users
    (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, 
    public_key TEXT NOT NULL UNIQUE,
    vault_location TEXT NOT NULL UNIQUE, otp_key TEXT UNIQUE)
    """)
    conn.commit()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS data
    (userid INTEGER PRIMARY KEY, session_key BLOB, nonce BLOB, tag BLOB, ciphertext BLOB, FOREIGN KEY(userid) REFERENCES users(id))""")
    conn.commit()
    conn.close()


# Function takes a username, public key, and,
# vault file name, and an otp secret key if one is provided.
def create_cybervault(username, vault):
    success = False

    if not username:
        return

    try:
        conn = sqlite3.connect(vault)
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS cybervault
        (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, website_url TEXT,
        username TEXT, password TEXT UNIQUE)
        """)
        success = True
    except AttributeError:
        os.remove(vault)

    if success:
        return True


def add_user(username, pub_key, key, vault_location):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()

    if key is not None:
        entities = [username, pub_key, vault_location, key]
        cursor.execute("""
        INSERT INTO users("username", "public_key", "vault_location", "otp_key") VALUES(?, ?, ?, ?)
        """, entities)

    else:
        entities = [username, pub_key, vault_location]
        cursor.execute("""
        INSERT INTO users("username", "public_key", "vault_location") VALUES(?, ?, ?)
        """, entities)

    conn.commit()
    last_id = cursor.lastrowid
    conn.close()

    return last_id


def add_user_enc_data(userid, session_key, nonce, tag, ciphertext):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()  
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()

    entities = [userid, session_key, nonce, tag, ciphertext]
    cursor.execute("""
    INSERT INTO data("userid", "session_key", "nonce", "tag", "ciphertext") VALUES(?, ?, ?, ?, ?)
    """, entities)

    conn.commit()
    conn.close()


def get_user(username):
    uname = None
    pkey = None
    vault_location = None
    otp_key = None

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))

    rows = cursor.fetchall()

    for row in rows:
        uid = row[0]
        uname = row[1]
        pkey = row[2]
        pkey = pkey.decode('utf-8')
        vault_location = row[3]
        otp_key = row[4]

    if uname:
        return uname, pkey, vault_location, otp_key, uid
    else:
        return

def add_entry(vault, entryname, url, user, passwd):
    conn = sqlite3.connect(vault)
    cursor = conn.cursor()

    name = entryname
    web_url = url
    username = user
    password = passwd

    entries = [name, web_url, username, password]
    cursor.execute("""
    INSERT INTO cybervault ("name", "website_url", "username", "password") VALUES(?, ?, ?, ?)
    """, entries)

    conn.commit()
    conn.close()

    return True
