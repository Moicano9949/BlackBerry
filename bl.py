from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

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
    print()

# ——— Edita estas rutas según tu entorno ———
CERT_PATH = 'cert/BlackBerry_Server.crt'
KEY_PATH  = 'cert/BlackBerry_Server.key'

# Llamada a funciones
mostrar_info_cert(CERT_PATH)
mostrar_info_key(KEY_PATH)
