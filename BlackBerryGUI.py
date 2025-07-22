#!/usr/bin/env python3
"""
app_gui.py

Interfaz gráfica en Python 3 con Tkinter para enviar comandos literalmente al cliente BlackBerry:
 - Iniciar/Detener servidor.
 - Lista de conexiones activas.
 - Selección de sesión con un clic.
 - Panel de detalles (IP, puerto, AES key).
 - Área de comandos: todo el texto que escribes se envía literalmente al cliente.
 - Área de respuesta: muestra la respuesta del cliente.

Autor: ChatGPT
Fecha: 25 de junio de 2025
"""
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import queue
import socket
import BlackBerry

class ServerControl(threading.Thread):
    def __init__(self, host, port, status_queue):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.status_queue = status_queue
        self.running = False

    def run(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(5)
            BlackBerry.server_socket = server
            BlackBerry.HOST = self.host
            BlackBerry.PORT = self.port
            threading.Thread(target=BlackBerry.accept_connections, args=(server,), daemon=True).start()
            self.running = True
            self.status_queue.put(f"Servidor iniciado en {self.host}:{self.port}")
        except Exception as e:
            self.status_queue.put(f"Error al iniciar servidor: {e}")

    def stop(self):
        with BlackBerry.conn_lock:
            for cid, (sock, _, _) in list(BlackBerry.connections.items()):
                try: sock.close()
                except: pass
            BlackBerry.connections.clear()
        try:
            BlackBerry.server_socket.close()
        except:
            pass
        self.running = False
        self.status_queue.put("Servidor detenido")

class GUIApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BlackBerry GUI Cliente")
        self.geometry("800x500")
        self.status_queue = queue.Queue()
        self.selected_cid = None
        self._build_ui()
        self._start_server()
        self._refresh()

    def _build_ui(self):
        # Panel superior: servidor
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(top, text="Host:").pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="0.0.0.0")
        ttk.Entry(top, textvariable=self.host_var, width=15).pack(side=tk.LEFT, padx=2)
        ttk.Label(top, text="Puerto:").pack(side=tk.LEFT)
        self.port_var = tk.IntVar(value=BlackBerry.PORT)
        ttk.Entry(top, textvariable=self.port_var, width=5).pack(side=tk.LEFT, padx=2)
        self.btn_toggle = ttk.Button(top, text="Iniciar Servidor", command=self._toggle_server)
        self.btn_toggle.pack(side=tk.LEFT, padx=5)
        self.lbl_status = ttk.Label(top, text="—")
        self.lbl_status.pack(side=tk.LEFT, padx=10)

        # Panel principal
        main = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Conexiones
        left = ttk.Labelframe(main, text="Conexiones")
        main.add(left, weight=1)
        self.lst_conn = tk.Listbox(left)
        self.lst_conn.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.lst_conn.bind('<<ListboxSelect>>', self._on_select)

        # Detalles + comandos + respuesta
        right = ttk.Frame(main)
        main.add(right, weight=3)

        # Detalles
        det = ttk.Labelframe(right, text="Detalles de Conexión")
        det.pack(fill=tk.X, padx=5, pady=5)
        self.lbl_details = ttk.Label(det, text="Seleccione una conexión")
        self.lbl_details.pack(anchor=tk.W, padx=5, pady=5)

        # Comando
        cmd_frame = ttk.Labelframe(right, text="Enviar Comando")
        cmd_frame.pack(fill=tk.X, padx=5, pady=5)
        self.cmd_entry = ttk.Entry(cmd_frame)
        self.cmd_entry.pack(fill=tk.X, padx=5, pady=5)
        self.cmd_entry.bind('<Return>', lambda e: self._send_cmd())
        send_btn = ttk.Button(cmd_frame, text="Enviar", command=self._send_cmd)
        send_btn.pack(pady=5)

        # Respuesta
        resp_frame = ttk.Labelframe(right, text="Respuesta del Cliente")
        resp_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.txt_resp = tk.Text(resp_frame, wrap=tk.WORD)
        self.txt_resp.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.txt_resp.config(state=tk.DISABLED)

    def _start_server(self):
        host, port = self.host_var.get(), self.port_var.get()
        self.server_ctrl = ServerControl(host, port, self.status_queue)
        self.server_ctrl.start()
        self.btn_toggle.config(text="Detener Servidor")

    def _toggle_server(self):
        if getattr(self, 'server_ctrl', None) and self.server_ctrl.running:
            self.server_ctrl.stop()
            self.btn_toggle.config(text="Iniciar Servidor")
        else:
            self._start_server()

    def _refresh(self):
        # Actualiza estado y lista conexiones
        try:
            msg = self.status_queue.get_nowait()
            self.lbl_status.config(text=msg)
        except queue.Empty:
            pass
        self.lst_conn.delete(0, tk.END)
        with BlackBerry.conn_lock:
            for cid, (_, addr, _) in BlackBerry.connections.items():
                self.lst_conn.insert(tk.END, f"{cid}: {addr[0]}:{addr[1]}")
        self.after(1000, self._refresh)

    def _on_select(self, event):
        sel = self.lst_conn.curselection()
        if sel:
            self.selected_cid = int(self.lst_conn.get(sel[0]).split(':')[0])
            with BlackBerry.conn_lock:
                _, addr, aes = BlackBerry.connections[self.selected_cid]
            details = f"ID: {self.selected_cid} | IP: {addr[0]} | Puerto: {addr[1]} | AES: {aes.hex()}"
            self.lbl_details.config(text=details)
            # Limpia respuestas anteriores
            self.txt_resp.config(state=tk.NORMAL)
            self.txt_resp.delete('1.0', tk.END)
            self.txt_resp.config(state=tk.DISABLED)
        else:
            self.selected_cid = None
            self.lbl_details.config(text="Seleccione una conexión")

    def _send_cmd(self):
        if self.selected_cid is None:
            messagebox.showwarning("Atención", "Primero seleccione una conexión")
            return
        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return
        with BlackBerry.conn_lock:
            sock, _, aes = BlackBerry.connections[self.selected_cid]
        try:
            BlackBerry.send_encrypted_message(sock, cmd, aes)
            resp = BlackBerry.receive_encrypted_message(sock, aes)
            if resp is None:
                resp = "<no hubo respuesta>"
        except Exception as e:
            resp = f"Error de comunicación: {e}"
        # Mostrar
        self.txt_resp.config(state=tk.NORMAL)
        self.txt_resp.insert(tk.END, f"> {cmd}\n{resp}\n\n")
        self.txt_resp.see(tk.END)
        self.txt_resp.config(state=tk.DISABLED)
        self.cmd_entry.delete(0, tk.END)

if __name__ == '__main__':
    GUIApp().mainloop()
