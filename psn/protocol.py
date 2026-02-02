# -*- coding: utf-8 -*-
"""
Created on Mon Feb  2 17:55:11 2026

@author: Lenovo
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import json, os

def encrypt_message(key: bytes, payload: dict) -> dict:
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    data = json.dumps(payload).encode()
    ciphertext = aead.encrypt(nonce, data, None)
    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }

def decrypt_message(key: bytes, message: dict) -> dict:
    aead = ChaCha20Poly1305(key)
    plaintext = aead.decrypt(
        bytes.fromhex(message["nonce"]),
        bytes.fromhex(message["ciphertext"]),
        None
    )
    return json.loads(plaintext.decode())
