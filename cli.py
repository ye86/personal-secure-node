# -*- coding: utf-8 -*-
"""
Created on Mon Feb  2 17:55:34 2026

@author: Lenovo
"""

from psn.identity import load_or_create_identity
from psn.crypto import generate_ephemeral_keypair, derive_session_key
from psn.protocol import encrypt_message, decrypt_message

def main():
    print("PSN v0.1 CLI Demo")

    identity = load_or_create_identity()
    eph_priv, eph_pub = generate_ephemeral_keypair()

    # 演示：假设对方已给你它的临时公钥
    peer_pub = eph_pub.public_bytes_raw()
    session_key = derive_session_key(eph_priv, peer_pub)

    msg = {"type": "DATA", "content": "Hello from PSN"}
    encrypted = encrypt_message(session_key, msg)
    decrypted = decrypt_message(session_key, encrypted)

    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)

if __name__ == "__main__":
    main()