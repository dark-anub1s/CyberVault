import os
import time
import base64
import random
import string
import hashlib
import requests
import zipfile
import pyperclip
from pathlib import Path
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

if os.name == 'nt':
    import winreg


# Done
def clipboard_wipe(enabled=False, sleep_time=5):
    while enabled:
        pyperclip.copy("")
        time.sleep(sleep_time)


# Done
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


# Done
def rsa_vault_encrypt(public_key, password):
    # home = Path.home()
    # home = os.path.join(home, "Documents")
    # vault_dir = os.path.join(home, "CyberVault")
    # data_file = os.path.join(vault_dir, "data.bin")

    # if not os.path.isdir(vault_dir):
    #     os.makedirs(vault_dir)

    data = password.encode('utf-8')
    key = RSA.import_key(public_key)
    session_key = get_random_bytes(32)

    # Encrypt the session key with public RSA key
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data (Password) with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    return enc_session_key, cipher_aes.nonce, tag, ciphertext
    # with open(data_file, 'wb') as f:
    #     for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext):
    #         f.write(x)


# Done
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


# Done
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


# Done
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


def get_reg_key():
    user_db_code = None
    with winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_CONFIG) as hkey:
        with winreg.OpenKey(hkey, "SOFTWARE", 0, winreg.KEY_READ) as sub_key:
            with winreg.CreateKeyEx(sub_key, "CyberVault", 0, winreg.KEY_READ) as vault_key:
                try:
                    for x in range(100):
                        key = winreg.EnumKey(sub_key, x)
                        if key == 'CyberVault':
                            user_db_code = winreg.EnumValue(vault_key, 0)[1]

                except OSError:
                    pass
            sub_key.Close()
        hkey.Close()
    if user_db_code:
        return user_db_code


def user_db_enc(file, key):
    vkey = base64.b64decode(key)
    vkey = vkey.decode("UTF-8")
    aes_vault_encryption(file, vkey)


def user_db_dec(file, key):
    vkey = base64.b64decode(key)
    vkey = vkey.decode("UTF-8")
    ase_vault_decryption(file, vkey)


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


def generate_password(upper, lower, digit, special, pass_label, length):
    """ Length will default to 0, this can be passed in on the call if you chose. strength is set by default to strong.
This parameter is what sets the complexity of the password (weak, strong, very)."""

    pass_list = ""
    password = ""

    if upper:
        pass_list += string.ascii_uppercase

    if lower:
        pass_list += string.ascii_lowercase

    if digit:
        pass_list += string.digits

    if special:
        pass_list += string.punctuation

    for _ in range(1):
        # Human Readable password
        password = "".join(random.choices(pass_list, k=length))

    pass_label.set(password)


def pwn_checker(password):
    # Add in function to check a single password or a complete list of passwords.
    sha_password = hashlib.sha1(password.encode()).hexdigest()

    sha_prefix = sha_password[0:5]
    sha_postfix = sha_password[5:].upper()

    url = f"https://api.pwnedpasswords.com/range/{sha_prefix}"

    payload = {}
    headers = {}
    pwned_dict = {}

    response = requests.request('GET', url, headers=headers, data=payload)

    pwned_list = response.text.split('\r\n')

    for pwned_pass in pwned_list:
        pwned_hash = pwned_pass.split(":")
        pwned_dict[pwned_hash[0]] = pwned_hash[1]

    if sha_postfix in pwned_dict.keys():
        return True, pwned_dict[sha_postfix]
    else:
        return False, 0

def backup_account(save_location):
    backup_location = Path(save_location)
    save_location = os.path.join(backup_location, 'cybervault_backup.zip')
    backup = zipfile.ZipFile(save_location, 'w')

    backup.write()
    backup.close()

