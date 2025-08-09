# ---------------------------------------------------------------------
# Sec-Sci Create_Signed_JWT_RSA-SHA256_Manual v1.0.250809 - August 2025
# ---------------------------------------------------------------------
# Tool:      Sec-Sci Create_Signed_JWT_RSA-SHA256_Manual v1.0.250809
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2025 WWW.SECURITY-SCIENCE.COM

# Generate a 2048-bit private key
# $ openssl genrsa -out private.pem 2048

# Extract the public key
# $ openssl rsa -in private.pem -pubout -out public.pem

import jwt
import json, base64, datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

# Header & Payload
header = {
    "alg": "RS256",
    "typ": "JWT"
}

now = datetime.datetime.now(datetime.UTC)

payload = {
    "iss": "issuer",
    "sub": "subject",
    "aud": "recipient",
    "exp": int((now + datetime.timedelta(minutes=15)).timestamp()),
    "iat": int(now.timestamp())
}

encoded_header = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
encoded_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

# Load Private Key
with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Sign With Private Key
message = f"{encoded_header}.{encoded_payload}".encode()
signature = private_key.sign(
    message,
    padding.PKCS1v15(),
    hashes.SHA256()
)

encoded_signature = b64url_encode(signature)
jwt_token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"
print(jwt_token)

# Verify JWT Token
# Load Public Key
with open("public.pem", "rb") as f:
    public_key = f.read()

decoded = jwt.decode(jwt_token, public_key, algorithms=["RS256"], audience="recipient")
print(decoded)