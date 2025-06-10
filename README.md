# NetSpy 🕵️‍♂️💻👁

![Logo de NetSpy](file_00000000ee34622f93dc7fc91766870a_conversation_id=680be191-1d6c-800d-afee-f53b5669f483&message_id=7b1e12db-2a84-41e3-9368-a162739b0293.png)

NetSpy es una herramienta avanzada de monitoreo y control remoto, diseñada para fines educativos y para pruebas de penetración éticas. Integrada en el proyecto [SocietySpy](https://github.com/Moicano9949/SocietySpy), NetSpy se destaca por su arquitectura modular, su versatilidad en la generación de payloads y su facilidad para establecer conexiones remotas a nivel global.

## Características Principales

- **Generación de Payloads Personalizados:**  
  Incorpora el script `payloadG.py` para crear payloads adaptados específicamente a los entornos de destino.

- **Control de Conexiones Remotas:**  
  Permite gestionar múltiples sesiones y ejecutar comandos en equipos clientes de forma remota.

- **Registro y Seguimiento de Eventos:**  
  Realiza un seguimiento detallado de todas las conexiones y actividades a través del archivo `netspy_server.log`.

- **Soporte para Conexiones Globales:**  
  Se recomienda el uso de [Serveo](https://serveo.net/) para exponer el puerto local, permitiendo así conexiones remotas desde cualquier parte del mundo.
   ```bash
  ssh -R 9949:localhost:9949 serveo.net

- **Modo Ofuscado:**  
  Ofrece opciones de ofuscación que facilitan la evasión en entornos controlados, incrementando la seguridad durante las pruebas.

## Instalación e Inicio

1. **Clonar el Repositorio y Acceder al Directorio de NetSpy:**

   ```bash
   git clone https://github.com/Moicano9949/SocietySpy.git
   cd SocietySpy/NetSpy
# BlackBerry
# BlackBerry
