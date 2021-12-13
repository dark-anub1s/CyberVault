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
    (username TEXT PRIMARY KEY NOT NULL, public_key TEXT UNIQUE,
    vault_location TEXT, otp_key TEXT)
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
        (id INT PRIMARY KEY, website_url TEXT, name TEXT,
        username TEXT, password TEXT)
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
    conn = sqlite3.connect('vault_users.cdbv')
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