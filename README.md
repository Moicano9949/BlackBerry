# BlackBerry(Net)

![Logo de BlackBerry](file_00000000ee34622f93dc7fc91766870a_conversation_id=680be191-1d6c-800d-afee-f53b5669f483&message_id=7b1e12db-2a84-41e3-9368-a162739b0293.png)

BlackBerry es una herramienta de monitoreo y control remoto, diseñada para fines educativos.

## Características Principales

- **Generación de Payloads Personalizados:**  
  Incorpora el script `payloadG.py` para crear payloads basicos en python3(puedes perzoanlisarlo)

- **Control de Conexiones Remotas:**  
  Permite gestionar múltiples sesiones y ejecutar comandos en equipos clientes de forma remota.

- **Registro y Seguimiento de Eventos:**  
  Realiza un seguimiento detallado de todas las conexiones y actividades en `logs/`.

- **Soporte para Conexiones Globales:**  
  Se recomienda el uso de [Serveo](https://serveo.net/) para exponer el puerto local, permitiendo así conexiones remotas desde cualquier dispositivo con conexion.
   ```bash
  ssh -R 9949:localhost:9949 serveo.net

## Instalación e Inicio

1. **Clonar el Repositorio:**

   ```bash
   git clone https://github.com/Moicano9949/SocietySpy.git
   cd BlackBerry

2. **Ejecuta BlackBerry(server):**
    ```bash
    python3 BlackBerry.py
    BlackBerry> help
# BlackBerry
# BlackBerry
