import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization



private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serialização das chaves RSA em formato PEM (Base64 interna)
private_der = private_key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

public_key = private_key.public_key()
public_der = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

result = {
    "private_key": base64.b64encode(private_der).decode('utf-8'),
    "public_key": base64.b64encode(public_der).decode('utf-8')
}


print(json.dumps(result))

