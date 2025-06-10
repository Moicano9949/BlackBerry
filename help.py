import sys
from colores import *

def guia_linux():
    return f"""{start} {b_blue}GUÍA PARA RECOLECCIÓN DE INFORMACIÓN EN LINUX{reset}

{bold}1. Información del sistema:{reset}
  {eje} {b_green}whoami{reset}                  → Usuario actual
  {eje} {b_green}uname -a{reset}                → Detalles del kernel
  {eje} {b_green}cat /etc/os-release{reset}    → Versión del sistema operativo

{bold}2. Usuarios y permisos:{reset}
  {eje} {b_green}cat /etc/passwd{reset}         → Lista de usuarios
  {eje} {b_green}sudo -l{reset}                 → Ver qué puede hacer el usuario con sudo
  {eje} {b_green}id{reset}                      → Ver UID, GID y grupos

{bold}3. Procesos y servicios activos:{reset}
  {eje} {b_green}ps aux{reset}                  → Procesos en ejecución
  {eje} {b_green}netstat -tulnp{reset}          → Puertos abiertos y procesos asociados

{bold}4. Archivos sensibles y contraseñas:{reset}
  {eje} {b_green}cat ~/.bash_history{reset}     → Historial de comandos
  {eje} {b_green}find / -name '*.log' 2>/dev/null{reset} → Buscar logs
  {eje} {b_green}cat /etc/shadow{reset}         → Hashes de contraseñas (requiere root)
"""

def guia_windows():
    return f"""{start} {b_blue}GUÍA PARA RECOLECCIÓN DE INFORMACIÓN EN WINDOWS{reset}

{bold}1. Información del sistema:{reset}
  {eje} {b_green}whoami{reset}                  → Usuario actual
  {eje} {b_green}systeminfo{reset}              → Información del sistema
  {eje} {b_green}hostname{reset}                → Nombre del host

{bold}2. Usuarios y permisos:{reset}
  {eje} {b_green}net user{reset}                → Listar usuarios del sistema
  {eje} {b_green}whoami /priv{reset}            → Ver privilegios del usuario
  {eje} {b_green}net localgroup Administrators{reset} → Ver administradores

{bold}3. Procesos y servicios activos:{reset}
  {eje} {b_green}tasklist{reset}                → Ver procesos en ejecución
  {eje} {b_green}netstat -ano{reset}            → Ver conexiones y puertos abiertos

{bold}4. Archivos sensibles y contraseñas:{reset}
  {eje} {b_green}type C:\\Windows\\System32\\drivers\\etc\\hosts{reset} → Hosts
  {eje} {b_green}dir C:\\Users\\%USERNAME%\\Recent{reset} → Archivos recientes
"""

def guia_android():
    return f"""{start} {b_blue}GUÍA PARA RECOLECCIÓN DE INFORMACIÓN EN ANDROID{reset}

{bold}1. Información del sistema:{reset}
  {eje} {b_green}getprop ro.product.model{reset} → Modelo del dispositivo
  {eje} {b_green}getprop ro.build.version.release{reset} → Versión de Android

{bold}2. Usuarios y permisos:{reset}
  {eje} {b_green}whoami{reset}                  → Usuario actual
  {eje} {b_green}cat /data/system/users.xml{reset} → Usuarios registrados

{bold}3. Procesos y servicios activos:{reset}
  {eje} {b_green}ps aux{reset}                  → Ver procesos en ejecución
  {eje} {b_green}netstat -tulnp{reset}          → Puertos abiertos

{bold}4. Archivos y almacenamiento:{reset}
  {eje} {b_green}ls -lah /storage/emulated/0{reset} → Ver archivos en almacenamiento interno
  {eje} {b_green}pm list packages -f{reset}     → Aplicaciones instaladas
"""

def main():
    if len(sys.argv) != 2:
        print(f"{alert} {b_red}Uso: python3 help.py [android/windows/linux]{reset}")
        sys.exit(1)

    option = sys.argv[1].lower()

    if option == "linux":
        print(guia_linux())
    elif option == "windows":
        print(guia_windows())
    elif option == "android":
        print(guia_android())
    else:
        print(f"{alert} {b_red}Parámetro no reconocido. Usa: linux, windows o android.{reset}")

if __name__ == "__main__":
    main()
