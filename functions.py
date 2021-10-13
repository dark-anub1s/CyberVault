import os
import time
import base64
import random
import winreg
import string
import pyperclip
from pathlib import Path
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def clipboard_wipe(sleep_time=5):
    while True:
        pyperclip.copy("")
        time.sleep(sleep_time)


def generate_keys():
    modules_length = 2048

    # Create a public/private keypair
    private_key = RSA.generate(modules_length, Random.new().read)
    public_key = private_key.public_key()

    # Export the keys into a usable format.
    private_key = private_key.export_key('PEM')
    public_key = public_key.export_key()

    # return the keys
    return private_key,  public_key


def rsa_vault_encrypt(public_key, password):
    home = Path.home()
    home = os.path.join(home, "Documents")
    vault_dir = os.path.join(home, "CyberVault")
    data_file = os.path.join(vault_dir, "data.bin")

    if not os.path.isdir(vault_dir):
        os.makedirs(vault_dir)

    data = password.encode('utf-8')
    key = RSA.import_key(public_key)
    session_key = get_random_bytes(32)

    # Encrypt the session key with public RSA key
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data (Password) with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    with open(data_file, 'wb') as f:
        for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext):
            f.write(x)


def rsa_vault_decrypt(private_key):
    home = Path.home()
    home = os.path.join(home, "Documents")
    vault_dir = os.path.join(home, "CyberVault")
    data_file = os.path.join(vault_dir, "data.bin")

    with open(private_key, 'r') as pri_key:
        key = RSA.import_key(pri_key.read())
        with open(data_file, 'rb') as f:
            # esk = enc_session_key, ctext = ciphertext
            esk, nonce, tag, ctext = [f.read(x) for x in
                                            (key.size_in_bytes(), 16, 16, -1)]

        # Decrypt session key with private key.
        cipher_rsa = PKCS1_OAEP.new(key)
        session_key = cipher_rsa.decrypt(esk)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ctext, tag)
        return data.decode("utf-8")


def aes_vault_encrypt(filename, key):
    key = key.encode("utf-8")
    key = pad(key, AES.block_size)

    # Open and encrypt vault data
    with open(filename, 'rb') as vault:
        data = vault.read()
        cipher = AES.new(key, AES.MODE_CFB)
        ciphertext = cipher.encrypt(data, AES.block_size)
        iv = base64.b64encode(cipher.iv).decode("utf-8")
        ciphertext = base64.b64encode(ciphertext).decode("utf-8")
    vault.close()

    # Write encrypted vault data back to same file.
    with open(filename, 'w') as data:
        data.write(iv + ciphertext)
    data.close()


def aes_vault_decrypt(filename, key):
    key = key.encode("utf-8")
    key = pad(key, AES.block_size)

    with open(filename, 'r') as vault_data:
        try:
            data = vault_data.read()
            length = len(data)
            iv = data[:24]
            iv = base64.b64decode(iv)
            ciphertext = data[24:length]
            ciphertext = base64.b64decode(ciphertext)

            cipher = AES.new(key, AES.MODE_CFB, iv)
            decrypted = cipher.decrypt(ciphertext)

            decrypted = unpad(decrypted, AES.block_size)
            with open(filename, 'wb') as vault:
                vault.write(decrypted)
        except (ValueError, KeyError):
            pass


# Create registry key to store password used to encrypt vault_users.cdbv file.
def create_vault_key():
    with winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_CONFIG) as hkey:
        with winreg.OpenKey(hkey, "SOFTWARE", 0, winreg.KEY_READ) as sub_key:
            with winreg.CreateKeyEx(sub_key, "CyberVault", 0,
                                    winreg.KEY_ALL_ACCESS) as vault_key:
                password = vault_password()
                password = password.encode("UTF-8")
                to_save = base64.b64encode(password)
                store = to_save.decode("UTF-8")
                winreg.SetValueEx(vault_key, "Code", 0, winreg.REG_SZ, store)
            vault_key.Close()
        sub_key.Close()
    hkey.Close()


def vault_password():
    pass_list = ""
    password = ""

    pass_list += string.ascii_lowercase
    pass_list += string.ascii_uppercase
    pass_list += string.digits
    pass_list += string.punctuation

    for _ in range(1):
        # Human Readable password
        password = "".join(random.choices(pass_list, k=25))
    return password
