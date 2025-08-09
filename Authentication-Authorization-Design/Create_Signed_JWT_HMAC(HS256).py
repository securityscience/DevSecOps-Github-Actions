# ---------------------------------------------------------------
# Sec-Sci Create_Signed_JWT_HMAC(HS256) v1.0.250809 - August 2025
# ---------------------------------------------------------------
# Tool:      Sec-Sci Create_Signed_JWT_HMAC(HS256) v1.0.250809
# Site:      www.security-science.com
# Email:     RnD@security-science.com
# Creator:   ARNEL C. REYES
# @license:  GNU GPL 3.0
# @copyright (C) 2025 WWW.SECURITY-SCIENCE.COM

import hashlib
import hmac
import json
import base64
import datetime
import jwt

secret = "$3<r3+"

header = {
    "alg": "HS256",
    "typ": "JWT"
}

now = datetime.datetime.now(datetime.UTC)  # timezone-aware current time

payload = {
    "iss": "issuer",
    "sub": "subject",
    "aud": "recipient",
    "exp": int((now + datetime.timedelta(minutes=15)).timestamp()),  # expires in 15 mins
    "iat": int(now.timestamp())
}

def b64url_encode(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

encoded_header = b64url_encode(header)
encoded_payload = b64url_encode(payload)

message = f"{encoded_header}.{encoded_payload}".encode()
signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()

# encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
# encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
# signature = hmac.new(secret.encode(), f"{encoded_header}.{encoded_payload}".encode(), hashlib.sha256).digest()

encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
jwt_token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"
print(jwt_token)

# Verify JWT Token
decoded = jwt.decode(jwt_token, secret, algorithms=["HS256"], audience="recipient")
print(decoded)