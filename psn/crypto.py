# -*- coding: utf-8 -*-
"""
Created on Mon Feb  2 17:54:50 2026

@author: Lenovo
"""

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

def generate_ephemeral_keypair():
    priv = x25519.X25519PrivateKey.generate()
    return priv, priv.public_key()

def derive_session_key(private_key, peer_public_key_bytes):
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared = private_key.exchange(peer_pub)
    return shared[:32]  # ChaCha20 key
