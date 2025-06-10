#!/usr/bin/env python3  
#NetSpy TCP Proxy Interceptor  
  
import socket  
import threading  
import argparse  
import logging  
import binascii  
import textwrap  
import time  
from datetime import datetime  
  
try:  
    from colorama import init, Fore, Style  
    init(autoreset=True)  
    USE_COLOR = True  
except ImportError:  
    USE_COLOR = False  
  
# Default configuration  
DEFAULT_LISTEN_HOST = '0.0.0.0'  
DEFAULT_LISTEN_PORT = 9949  
DEFAULT_TARGET_HOST = '0.0.0.0'  
DEFAULT_TARGET_PORT = 9948  
BUFFER_SIZE = 4096  # bytes  
  
  
def hexdump(data: bytes, width: int = 16) -> str:  
    """  
    Generate a classic hex dump (offset, hex bytes, ASCII) for the given data.  
    """  
    lines = []  
    for i in range(0, len(data), width):  
        chunk = data[i:i+width]  
        hex_bytes = ' '.join(f"{b:02X}" for b in chunk)  
        ascii_bytes = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in chunk)  
        lines.append(f"{i:04X}   {hex_bytes:<{width*3}}   {ascii_bytes}")  
    return '\n'.join(lines)  
  
  
def print_intercept(label: str, data: bytes):  
    """  
    Print timestamped, direction-labeled, length, and hex dump + ASCII.  
    """  
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  
    length = len(data)  
    header = f"[{timestamp}] {label} ({length} bytes)"  
    dump = hexdump(data)  
    if USE_COLOR:  
        header = Fore.CYAN + header + Style.RESET_ALL  
        dump = Fore.GREEN + dump + Style.RESET_ALL  
    print(header)  
    print(dump)  
    print('-' * 80)  
  
  
class ProxyServer:  
    def __init__(self, listen_host, listen_port, target_host, target_port):  
        self.listen_host = listen_host  
        self.listen_port = listen_port  
        self.target_host = target_host  
        self.target_port = target_port  
        self.running = False  
        self.server_socket = None  
  
    def start(self):  
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
        self.server_socket.bind((self.listen_host, self.listen_port))  
        self.server_socket.listen(5)  
        self.running = True  
        logging.info(f"Proxy listening on {self.listen_host}:{self.listen_port} -> {self.target_host}:{self.target_port}")  
  
        try:  
            while self.running:  
                client_sock, client_addr = self.server_socket.accept()  
                logging.info(f"Accepted connection from {client_addr}")  
                handler = threading.Thread(  
                    target=self.handle_client,  
                    args=(client_sock, client_addr),  
                    daemon=True  
                )  
                handler.start()  
        except KeyboardInterrupt:  
            logging.info("Keyboard interrupt received, shutting down proxy.")  
        finally:  
            self.shutdown()  
  
    def shutdown(self):  
        self.running = False  
        if self.server_socket:  
            try:  
                self.server_socket.close()  
                logging.info("Proxy server socket closed.")  
            except Exception as e:  
                logging.error(f"Error closing server socket: {e}")  
  
    def handle_client(self, client_socket, client_addr):  
        try:  
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
            server_socket.connect((self.target_host, self.target_port))  
            logging.info(f"Connected to target {self.target_host}:{self.target_port}")  
        except Exception as e:  
            logging.error(f"Cannot connect to target: {e}")  
            client_socket.close()  
            return  
  
        # Start bidirectional forwarding  
        threading.Thread(  
            target=self.forward,  
            args=(client_socket, server_socket, f"CLIENT->{self.target_host}"),  
            daemon=True  
        ).start()  
        threading.Thread(  
            target=self.forward,  
            args=(server_socket, client_socket, f"{self.target_host}->CLIENT"),  
            daemon=True  
        ).start()  
  
    def forward(self, source: socket.socket, destination: socket.socket, direction: str):  
        try:  
            while True:  
                data = source.recv(BUFFER_SIZE)  
                if not data:  
                    break  
                print_intercept(direction, data)  
                destination.sendall(data)  
        except Exception as e:  
            logging.error(f"Error in forwarding ({direction}): {e}")  
        finally:  
            source.close()  
            destination.close()  
            logging.info(f"Closed connection for {direction}")  
  
  
if __name__ == "__main__":  
    parser = argparse.ArgumentParser(description="TCP Proxy Interceptor with detailed logging")  
    parser.add_argument("--listen-host", default=DEFAULT_LISTEN_HOST,  
                        help="Local host to listen on")  
    parser.add_argument("--listen-port", type=int, default=DEFAULT_LISTEN_PORT,  
                        help="Local port to listen on")  
    parser.add_argument("--target-host", default=DEFAULT_TARGET_HOST,  
                        help="Remote target host to forward to")  
    parser.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT,  
                        help="Remote target port to forward to")  
    parser.add_argument("--verbose", action="store_true",  
                        help="Enable debug logging")  
    args = parser.parse_args()  
  
    level = logging.DEBUG if args.verbose else logging.INFO  
    logging.basicConfig(  
        level=level,  
        format="%(asctime)s [%(levelname)s] %(message)s",  
        datefmt="%Y-%m-%d %H:%M:%S"  
    )  
  
    proxy = ProxyServer(  
        args.listen_host,  
        args.listen_port,  
        args.target_host,  
        args.target_port  
    )  
    proxy.start()  
