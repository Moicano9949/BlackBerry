# BlackBerry(Net)

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
  ssh -R 9948:localhost:9948 serveo.net

## Instalación e Inicio

1. **Clonar el Repositorio:**

   ```bash
   git clone https://github.com/Moicano9949/BlackBerryV1.git
   cd BlackBerryV1

2. **Ejecuta BlackBerry(server):**
    ```bash
    python3 BlackBerry.py
    BlackBerry> help
# BlackBerry
# BlackBerry V1.0
