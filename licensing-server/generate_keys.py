"""Genera un par de claves Ed25519 nuevo para el servidor central de
licencias. Correr UNA sola vez (al desplegar el servidor por primera
vez) -- generar un par nuevo despues invalida la firma de todas las
respuestas que ya recibieron los clientes (tendrian que actualizar su
LICENSE_SERVER_PUBLIC_KEY).

Uso:
    python generate_keys.py

La clave PRIVADA va SOLO en el .env de este servidor
(LICENSE_SIGNING_PRIVATE_KEY) -- nunca se distribuye a ningun cliente.
La clave PUBLICA va en el .env de CADA instalacion on-prem
(LICENSE_SERVER_PUBLIC_KEY, ver .env.example en la raiz del repo) antes
de armar el .rar -- es publica por diseño, no hace falta protegerla."""
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

private_raw = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
public_raw = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)

print("=== Servidor central de licencias -- .env ===")
print(f"LICENSE_SIGNING_PRIVATE_KEY={base64.b64encode(private_raw).decode()}")
print()
print("=== Cada instalacion on-prem (.env.example / .env antes de armar el .rar) ===")
print(f"LICENSE_SERVER_PUBLIC_KEY={base64.b64encode(public_raw).decode()}")
