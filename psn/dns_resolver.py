# -*- coding: utf-8 -*-
"""
Created on Mon Feb  2 17:54:17 2026

@author: Lenovo
"""

import dns.resolver
import base64

def resolve_psn_key(domain: str) -> bytes:
    answers = dns.resolver.resolve(domain, "TXT")
    for rdata in answers:
        for txt in rdata.strings:
            record = txt.decode()
            if record.startswith("psn-key="):
                _, value = record.split("=", 1)
                return base64.b64decode(value)
    raise RuntimeError("No psn-key TXT record found")
