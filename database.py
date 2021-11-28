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
        CREATE TABLE IF NOT EXISTS vault
        (id INT PRIMARY KEY, website_url TEXT, name TEXT,
        username TEXT, password TEXT)
        """)
        success = True
    except AttributeError:
        os.remove(vault)

    if success:
        password = vault_password()
        rsa_vault_encrypt(pub, password)
