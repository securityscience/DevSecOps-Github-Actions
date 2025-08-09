# --------------------------------------------------------------------
# Sec-Sci Create_Signed_JWT_RSA-SHA256_pyJWT v1.0.250809 - August 2025
# --------------------------------------------------------------------
# Tool:      Sec-Sci Create_Signed_JWT_RSA-SHA256_pyJWT v1.0.250809
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
import datetime

# Create JWT Token
# Load Private Key
with open("private.pem", "rb") as f:
    private_key = f.read()

now = datetime.datetime.now(datetime.UTC)

payload = {
    "iss": "issuer",
    "sub": "subject",
    "aud": "recipient",
    "exp": int((now + datetime.timedelta(minutes=15)).timestamp()),
    "iat": int(now.timestamp())
}

# Sign With Private Key
jwt_token = jwt.encode(payload, private_key, algorithm="RS256")
print(jwt_token)

# Verify JWT Token
# Load Public Key
with open("public.pem", "rb") as f:
    public_key = f.read()

decoded = jwt.decode(jwt_token, public_key, algorithms=["RS256"], audience="recipient")
print(decoded)