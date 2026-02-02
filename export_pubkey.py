# -*- coding: utf-8 -*-
"""
Created on Mon Feb  2 18:02:23 2026

@author: Lenovo

please add to your domainname DNS
Type: TXT
Name: @
Value: psn-key=BASE64_PUBLIC_KEY
TTL: 300

"""

from psn.identity import load_or_create_identity
from cryptography.hazmat.primitives import serialization
import base64

key = load_or_create_identity().public_key()
raw = key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
print(base64.b64encode(raw).decode())
