#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import logging
import ssl
import socket
import time
from pathlib import Path
from collections import defaultdict, deque
import requests
import os

# ---------------- Configuración ----------------
LISTEN_HOST = '0.0.0.0'
DEFAULT_PORT = 9948
TARGET_HOST, TARGET_PORT = '127.0.0.1', 9949
CERTFILE, KEYFILE = 'cert/BlackBerry_Server.crt', 'cert/BlackBerry_Server.key'
BUFFER_SIZE = 4096
MAX_ACTIVE_IPS = 10
MAX_CONN_PER_SEC = 5
BLACKLIST_DURATION = 3600
REPORT_INTERVAL = 23 * 3600

LOG_SERVER_FILE = 'logs/BlackBerryServer.log'
LOG_PROXY_FILE = 'logs/BlackBerryTLSProxy.log'

active_ips = set()
conn_times = defaultdict(lambda: deque())
blacklist = {}
state_lock = threading.Lock()

TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
USE_TELEGRAM = False

logger = logging.getLogger("BlackBerryLogger")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
file_handler = logging.FileHandler(LOG_PROXY_FILE, encoding='utf-8')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

proxy_running = False
server_socket = None


# -------- Funciones para manejar logs en GUI --------
def read_log_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        return f"[ERROR leyendo {filepath}: {e}]"

def clear_log_file(filepath):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.truncate(0)
        return True
    except Exception as e:
        return False

# -------- GUI --------
class BlackBerryGUI:
    def __init__(self, root):
        self.root = root
        root.title("BlackBerry TLS Proxy")
        root.geometry("900x600")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True)

        # Pestaña Proxy
        self.tab_proxy = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_proxy, text="Proxy")

        self.port_frame = ttk.Frame(self.tab_proxy)
        self.port_frame.pack(pady=10, padx=10, anchor='w')

        ttk.Label(self.port_frame, text="Puerto Proxy:").pack(side='left')
        self.port_entry = ttk.Entry(self.port_frame, width=6)
        self.port_entry.pack(side='left', padx=(5, 20))
        self.port_entry.insert(0, str(DEFAULT_PORT))

        self.btn_start = ttk.Button(self.port_frame, text="Iniciar Proxy", command=self.start_proxy)
        self.btn_start.pack(side='left', padx=5)

        self.btn_stop = ttk.Button(self.port_frame, text="Detener Proxy", command=self.stop_proxy, state='disabled')
        self.btn_stop.pack(side='left', padx=5)

        self.info_label = ttk.Label(self.tab_proxy, text=f"Estado: Detenido", font=("Arial", 14))
        self.info_label.pack(pady=10)

        self.status_box = scrolledtext.ScrolledText(self.tab_proxy, state='disabled', height=25)
        self.status_box.pack(fill='both', expand=True, padx=10, pady=5)

        # Pestaña Log Server
        self.tab_log_server = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_log_server, text="Log Server")

        self.log_server_text = scrolledtext.ScrolledText(self.tab_log_server, state='disabled')
        self.log_server_text.pack(fill='both', expand=True, padx=10, pady=5)

        self.btn_clear_server = ttk.Button(self.tab_log_server, text="Limpiar Log Server", command=self.clear_server_log)
        self.btn_clear_server.pack(pady=5)

        # Pestaña Log Proxy
        self.tab_log_proxy = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_log_proxy, text="Log Proxy")

        self.log_proxy_text = scrolledtext.ScrolledText(self.tab_log_proxy, state='disabled')
        self.log_proxy_text.pack(fill='both', expand=True, padx=10, pady=5)

        self.btn_clear_proxy = ttk.Button(self.tab_log_proxy, text="Limpiar Log Proxy", command=self.clear_proxy_log)
        self.btn_clear_proxy.pack(pady=5)

        # Estado proxy y logs
        self.running = False
        self.server_thread = None

        # Refrescar logs periódicamente
        self.update_logs()

    def log(self, text):
        self.status_box.configure(state='normal')
        self.status_box.insert(tk.END, text + "\n")
        self.status_box.configure(state='disabled')
        self.status_box.see(tk.END)
        logger.info(text)

    def start_proxy(self):
        if self.running:
            messagebox.showinfo("Info", "El proxy ya está en ejecución.")
            return

        try:
            port = int(self.port_entry.get())
            if not (1 <= port <= 65535):
                raise ValueError("Puerto fuera de rango")
        except ValueError:
            messagebox.showerror("Error", "Por favor ingrese un puerto válido entre 1 y 65535")
            return

        global LISTEN_PORT
        LISTEN_PORT = port

        self.info_label.config(text=f"Estado: Iniciando proxy en puerto {LISTEN_HOST}:{LISTEN_PORT}...")
        self.port_entry.config(state='disabled')
        self.btn_start.config(state='disabled')
        self.btn_stop.config(state='normal')

        self.running = True
        self.server_thread = threading.Thread(target=start_proxy_server, args=(self.log,), daemon=True)
        self.server_thread.start()

    def stop_proxy(self):
        if not self.running:
            messagebox.showinfo("Info", "El proxy no está en ejecución.")
            return

        self.log("[INFO] Deteniendo proxy...")
        stop_proxy_server()
        self.running = False
        self.info_label.config(text="Estado: Detenido")
        self.port_entry.config(state='normal')
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        self.log("[INFO] Proxy detenido.")

    def update_logs(self):
        # Actualiza log Server
        server_log = read_log_file(LOG_SERVER_FILE)
        self.log_server_text.configure(state='normal')
        self.log_server_text.delete(1.0, tk.END)
        self.log_server_text.insert(tk.END, server_log)
        self.log_server_text.configure(state='disabled')
        self.log_server_text.see(tk.END)

        # Actualiza log Proxy
        proxy_log = read_log_file(LOG_PROXY_FILE)
        self.log_proxy_text.configure(state='normal')
        self.log_proxy_text.delete(1.0, tk.END)
        self.log_proxy_text.insert(tk.END, proxy_log)
        self.log_proxy_text.configure(state='disabled')
        self.log_proxy_text.see(tk.END)

        # Actualizar info proxy en pestaña proxy
        if self.running:
            self.info_label.config(text=f"Estado: Ejecutándose en {LISTEN_HOST}:{LISTEN_PORT}")
        else:
            self.info_label.config(text="Estado: Detenido")

        # Repetir cada 2 segundos
        self.root.after(2000, self.update_logs)

    def clear_server_log(self):
        if messagebox.askyesno("Confirmar", "¿Seguro que deseas limpiar el Log Server?"):
            if clear_log_file(LOG_SERVER_FILE):
                self.log("[INFO] Log Server limpiado.")
            else:
                messagebox.showerror("Error", "No se pudo limpiar el Log Server.")

    def clear_proxy_log(self):
        if messagebox.askyesno("Confirmar", "¿Seguro que deseas limpiar el Log Proxy?"):
            if clear_log_file(LOG_PROXY_FILE):
                self.log("[INFO] Log Proxy limpiado.")
            else:
                messagebox.showerror("Error", "No se pudo limpiar el Log Proxy.")

# -------- Funciones del servidor --------
def notify(text: str):
    if USE_TELEGRAM and TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        try:
            requests.post(f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage',
                          json={'chat_id': TELEGRAM_CHAT_ID, 'text': text, 'parse_mode': 'Markdown'})
        except Exception as e:
            logger.warning(f"Fallo al enviar mensaje: {e}")
    else:
        logger.info(text)

def set_keepalive(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

def hexdump(src, length=16):
    return '\n'.join(f"{i:04x}  {' '.join(f'{b:02x}' for b in src[i:i+length])}  {''.join(chr(b) if 32 <= b < 127 else '.' for b in src[i:i+length])}" for i in range(0, len(src), length))

def forward(src, dst, src_label, dst_label, log):
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            log(f"{src_label} → {dst_label}: {len(data)} bytes")
            log(hexdump(data))
            dst.sendall(data)
    except Exception as e:
        log(f"[ERROR] {src_label}->{dst_label}: {e}")
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except:
                pass
        log(f"[FIN] {src_label}->{dst_label}")

def handle_client(conn, addr, ssl_context, log):
    ip, port = addr
    now = time.time()
    set_keepalive(conn)

    with state_lock:
        if ip in blacklist and blacklist[ip] > now:
            conn.close()
            return
        if len(active_ips) >= MAX_ACTIVE_IPS and ip not in active_ips:
            blacklist[ip] = now + BLACKLIST_DURATION
            conn.close()
            return
        times = conn_times[ip]
        times.append(now)
        while times and now - times[0] > 1:
            times.popleft()
        if len(times) > MAX_CONN_PER_SEC:
            blacklist[ip] = now + BLACKLIST_DURATION
            conn.close()
            return
        active_ips.add(ip)

    client_label = f"Cliente({ip}:{port})"
    netspy_label = f"Backend({TARGET_HOST}:{TARGET_PORT})"
    log(f"[+] Nueva conexión: {client_label}")
    try:
        tls_conn = ssl_context.wrap_socket(conn, server_side=True)
        set_keepalive(tls_conn)

        for _ in range(3):
            try:
                srv = socket.create_connection((TARGET_HOST, TARGET_PORT))
                set_keepalive(srv)
                break
            except:
                time.sleep(1)
        else:
            raise ConnectionError("No se conectó al backend")

        threading.Thread(target=forward, args=(tls_conn, srv, client_label, netspy_label, log), daemon=True).start()
        threading.Thread(target=forward, args=(srv, tls_conn, netspy_label, client_label, log), daemon=True).start()
    except Exception as e:
        log(f"[ERROR] {client_label}: {e}")
        conn.close()
    finally:
        with state_lock:
            active_ips.discard(ip)
            conn_times.pop(ip, None)

def start_proxy_server(log_func):
    global proxy_running, server_socket
    proxy_running = True
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        set_keepalive(sock)
        try:
            sock.bind((LISTEN_HOST, LISTEN_PORT))
        except Exception as e:
            log_func(f"[ERROR] No se pudo enlazar al puerto {LISTEN_PORT}: {e}")
            proxy_running = False
            return
        sock.listen(5)
        server_socket = sock
        log_func(f"[INFO] Escuchando en {LISTEN_HOST}:{LISTEN_PORT}")
        while proxy_running:
            try:
                sock.settimeout(1.0)
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except Exception as e:
                log_func(f"[ERROR] Socket accept: {e}")
                break
            threading.Thread(target=handle_client, args=(conn, addr, ssl_context, log_func), daemon=True).start()

def stop_proxy_server():
    global proxy_running, server_socket
    proxy_running = False
    if server_socket:
        try:
            server_socket.close()
        except:
            pass
        server_socket = None

# -------- Función pública para lanzar GUI (modular) --------
def lanzar_gui_proxy():
    root = tk.Tk()
    app = BlackBerryGUI(root)
    root.mainloop()

# -------- Solo se ejecuta si este archivo es el principal --------
if __name__ == '__main__':
    lanzar_gui_proxy()
