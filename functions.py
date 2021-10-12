import os
import time
import base64
import random
import winreg
import string
from pathlib import Path
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


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
