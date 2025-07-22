#!/usr/bin/env python3
import socket
import ssl
import threading
import logging
import time
import requests
import os
import ipaddress
import argparse
import binascii
from collections import defaultdict, deque
from pathlib import Path

# ---------------- Configuración ----------------
LISTEN_HOST, LISTEN_PORT = '0.0.0.0', 9948
TARGET_HOST, TARGET_PORT = '127.0.0.1', 9949
CERTFILE, KEYFILE = 'cert/BlackBerry_Server.crt', 'cert/BlackBerry_Server.key'
BUFFER_SIZE = 4096
MAX_ACTIVE_IPS = 10
MAX_CONN_PER_SEC = 5
BLACKLIST_DURATION = 3600  # segundos
REPORT_INTERVAL = 23 * 3600  # 23 horas
LOG_FILE = 'logs/BlackBerryTLSProxy.log'

# ------------- Configuración de Logs -------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger()

# --------- Estado para Control de Acceso ---------
active_ips = set()
conn_times = defaultdict(lambda: deque())
blacklist = {}  # ip -> expiry timestamp
state_lock = threading.Lock()

# --------- Parámetros de Ejecución ---------
parser = argparse.ArgumentParser(description='BlackBerryTLSProxy')
parser.add_argument('--telegram', action='store_true', help='Habilita notificaciones por Telegram')
args = parser.parse_args()
USE_TELEGRAM = args.telegram

# --------- Token Telegram (opcional) ---------
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

# --------- Utilidades de Notificación ---------
def notify(text: str):
    if USE_TELEGRAM and TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
        payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': text, 'parse_mode': 'Markdown'}
        try:
            resp = requests.post(url, json=payload, timeout=5)
            resp.raise_for_status()
        except Exception as e:
            logger.warning(f"Fallo al enviar mensaje: {e}")
    else:
        logger.info(text)

def notify_document(path, caption=None):
    if USE_TELEGRAM and TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument'
        try:
            with open(path, 'rb') as f:
                files = {'document': f}
                data = {'chat_id': TELEGRAM_CHAT_ID, 'parse_mode': 'Markdown'}
                if caption: data['caption'] = caption
                resp = requests.post(url, data=data, files=files, timeout=10)
                resp.raise_for_status()
        except Exception as e:
            logger.warning(f"Fallo al enviar documento: {e}")
    else:
        logger.info(f"Documento: {path} {caption or ''}")

# -------- Funciones internas ---------

def blacklist_cleanup(now):
    with state_lock:
        expiradas = [ip for ip, exp in blacklist.items() if now >= exp]
        for ip in expiradas:
            del blacklist[ip]
            logger.info(f"IP {ip} removida de la lista negra automáticamente")
            notify(f"[ListaNegra] IP removida: `{ip}`")


def set_keepalive(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, 'TCP_KEEPIDLE'):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 30)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)


def hexdump(src, length=16):
    result = []
    for i in range(0, len(src), length):
        chunk = src[i:i+length]
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
        ascii_bytes = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
        result.append(f"{i:04x}  {hex_bytes:<{length*3}}  {ascii_bytes}")
    return '\n'.join(result)


def forward(src, dst, src_label, dst_label):
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            # Detalle de tráfico crudo en hexdump
            logger.info(f"{src_label} → {dst_label}: {len(data)} bytes")
            dump = hexdump(data)
            for line in dump.splitlines():
                logger.info(line)
            dst.sendall(data)
    except Exception as e:
        logger.warning(f"Excepción {src_label}->{dst_label}: {e}")
        notify(f"[Error] {src_label}->{dst_label}: {e}")
    finally:
        for s in (src, dst):
            try: s.shutdown(socket.SHUT_RDWR); s.close()
            except: pass
        logger.info(f"Conexión finalizada {src_label}->{dst_label}")
        notify(f"[Desconexión] {src_label}->{dst_label}")


def handle_client(conn, addr):
    ip, port = addr
    now = time.time()
    set_keepalive(conn)

    blacklist_cleanup(now)
    with state_lock:
        if ip in blacklist:
            logger.warning(f"IP en lista negra: {ip}")
            conn.close(); return
        if len(active_ips) >= MAX_ACTIVE_IPS and ip not in active_ips:
            blacklist[ip] = now + BLACKLIST_DURATION
            logger.warning(f"Máximo IPs, bloqueando {ip}")
            notify(f"[ListaNegra] {ip} bloqueada")
            conn.close(); return
        # Rate limiting
        times = conn_times[ip]; times.append(now)
        while times and now - times[0] > 1: times.popleft()
        if len(times) > MAX_CONN_PER_SEC:
            blacklist[ip] = now + BLACKLIST_DURATION
            logger.warning(f"Rate limit excedido: {ip}")
            notify(f"[RateLimit] {ip} excedió {MAX_CONN_PER_SEC}/s")
            conn.close(); return
        active_ips.add(ip)

    client_label = f"Cliente({ip}:{port})"
    netspy_label = f"BlackBerry(server)({TARGET_HOST}:{TARGET_PORT})"
    logger.info(f"Nueva conexión de {client_label}")
    notify(f"[NuevaConexión] {client_label} establecida")
    try:
        tls_conn = ssl_context.wrap_socket(conn, server_side=True)
        set_keepalive(tls_conn)
        logger.info(f"TLS OK con {client_label}")
        notify(f"[TLS] {client_label}")
        # Conexión al backend
        for i in range(3):
            try:
                srv = socket.create_connection((TARGET_HOST, TARGET_PORT))
                set_keepalive(srv)
                logger.info(f"Conectado backend {netspy_label}")
                notify(f"[Proxy] Backend conectado en intento {i+1}")
                break
            except Exception as e:
                logger.error(f"Error backend (int {i+1}): {e}")
                time.sleep(1)
        else:
            raise ConnectionError("No se conectó al backend")
        # Hilos de reenvío
        threading.Thread(target=forward, args=(tls_conn, srv, client_label, netspy_label), daemon=True).start()
        threading.Thread(target=forward, args=(srv, tls_conn, netspy_label, client_label), daemon=True).start()
    except Exception as e:
        logger.error(f"Error cliente {client_label}: {e}")
        notify(f"[Error] {client_label}: {e}")
        conn.close()
    finally:
        with state_lock:
            active_ips.discard(ip); conn_times.pop(ip, None)


def scheduled_report():
    if Path(LOG_FILE).exists() and Path(LOG_FILE).stat().st_size > 0:
        notify_document(LOG_FILE, caption='[Reporte] Registro actual')
        open(LOG_FILE, 'w').close()
        logger.info("Reporte enviado, log truncado")
    threading.Timer(REPORT_INTERVAL, scheduled_report).start()

if __name__ == '__main__':
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    scheduled_report()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        set_keepalive(sock)
        sock.bind((LISTEN_HOST, LISTEN_PORT)); sock.listen(5)
        logger.info(f"BlackBerryTLSProxy escuchando en {LISTEN_HOST}:{LISTEN_PORT}")
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
