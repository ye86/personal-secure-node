# -*- coding: utf-8 -*-
"""
Created on Mon Feb  2 18:06:36 2026

@author: Lenovo
"""

import socket
import json

def listen(port=7000):
    s = socket.socket()
    s.bind(("0.0.0.0", port))
    s.listen(1)
    conn, addr = s.accept()
    data = conn.recv(8192)
    conn.close()
    return json.loads(data.decode())

def send(host, port, payload):
    s = socket.socket()
    s.connect((host, port))
    s.send(json.dumps(payload).encode())
    s.close()
