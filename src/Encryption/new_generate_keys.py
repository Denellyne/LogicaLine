import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

if os.path.exists("private_key.pem"):
    os.remove("private_key.pem")
if os.path.exists("public_key.pem"):
    os.remove("public_key.pem")

# Gerar chave privada RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serializar chave privada em PEM (sem criptografia)
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

with open("private_key.pem", "wb") as f:
    f.write(pem_private)

# Serializar chave pública em PEM
public_key = private_key.public_key()
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("public_key.pem", "wb") as f:
    f.write(pem_public)

print("Chaves RSA geradas e salvas em 'private_key.pem' e 'public_key.pem'")

