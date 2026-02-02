# -*- coding: utf-8 -*-
"""
Created on Mon Feb  2 17:53:14 2026

@author: Lenovo
"""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import os

KEY_FILE = "identity.key"

def load_or_create_identity():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    private_key = ed25519.Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(KEY_FILE, "wb") as f:
        f.write(pem)
    return private_key

