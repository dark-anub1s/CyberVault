import os
import sqlite3
from PyQt5.QtWidgets import QMessageBox
from functions import vault_password, rsa_vault_encrypt


# Create the main users database
def create_db():
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users
    (id int PRIMARY KEY AUTO_INCREMENT, username TEXT NOT NULL UNIQUE, 
    public_key TEXT NOT NULL UNIQUE,
    vault_location TEXT NOT NULL UNIQUE, otp_key TEXT UNIQUE)
    """)

    cur.execute("""CREATE TABLE IF NOT EXISTS data
        (userID int PRIMARY KEY, FOREIGN KEY(userID) REFERENCES users(id)
        , enc_session_key TEXT, cipher_aes.nonce TEXT, tag TEXT, ciphertext TEXT)
     """)

    conn.commit()
    conn.close()


# Function takes a username, public key, and,
# vault file name, and an otp secret key if one is provided.
def create_cybervault(username, pub, vault, otp_key=None):
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
        add_user(username, pub, otp_key, vault)
        password = vault_password()
        rsa_vault_encrypt(pub, password)


def add_user(username, pub_key, key, vault_location):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

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
        uname = row[0]
        pkey = row[1]
        pkey = pkey.decode('utf-8')
        vault_location = row[2]
        otp_key = row[3]

    if uname:
        return uname, pkey, vault_location, otp_key
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
