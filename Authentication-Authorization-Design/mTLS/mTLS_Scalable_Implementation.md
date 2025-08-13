# Ultimate mTLS (Mutual TLS) Implementation Guide

A **complete end-to-end "step-by-step guide"** for mTLS with mobile devices (iOS/Android), including **Root + Intermediate CA**, **Server Certificates**, **Client Certificates (Scalable Strategies)**, **Nginx Configuration**, **Installation Steps on iOS**, **`curl`/Python Tests**, **Certificate Renewal/Revocation**, and **Scale-Out Distribution Options**.

> Works on **Linux/macOS** or **Windows (with Git Bash or WSL)**.
> If strictly on native Windows PowerShell, few PowerShell equivalents are included where it really matters.


## Prerequisites & Layout

* Install OpenSSL and (optionally) Git Bash/WSL on Windows.
* Pick a working folder (example):

```
mtls/
  ca/
  server/
  clients/
  nginx/
```

* Decide **hostnames/IPs** to be used to reach the server:
   
  * Example: `api.example.local`, `192.168.1.50`, and `localhost`.
   
  * Define a few variables (replace as needed).


## 1) Create a Root CA (offline) & Intermediate CA (for issuing)

> Best practice: Root CA signs only the Intermediate; Intermediate signs server & client certs.

### 1.1 Root CA

```bash
mkdir -p mtls/ca && cd mtls/ca

# Root private key (keep offline & secure)
openssl genrsa -out rootCA.key 4096

# Self-signed Root certificate (10 years)
openssl req -x509 -new -sha256 -days 3650 \
  -key rootCA.key -out rootCA.crt \
  -subj "/C=US/ST=State/L=City/O=MyOrg/CN=MyOrg Root CA"
```

### 1.2 Intermediate CA

```bash
# Intermediate private key
openssl genrsa -out intermediateCA.key 4096

# Intermediate CSR
openssl req -new -sha256 -key intermediateCA.key -out intermediateCA.csr \
  -subj "/C=US/ST=State/L=City/O=MyOrg/CN=MyOrg Intermediate CA"

# Sign Intermediate with Root (pathlen=0, CA:TRUE)
cat > intermediate_ext.cnf <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

openssl x509 -req -in intermediateCA.csr \
  -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
  -out intermediateCA.crt -days 1825 -sha256 \
  -extfile intermediate_ext.cnf
```

**Distribute to servers/clients:**

* **Trust anchor for clients**: normally just `rootCA.crt`.
* **Issuing CA for validation on server**: `intermediateCA.crt` (and sometimes full chain).


## 2) Create the Server Cert (with SAN & EKU)

> Include **all** hostnames/IPs to be used (Safari/iOS is strict).

```bash
cd ../server
# Server key
openssl genrsa -out server.key 2048

# Server CSR with SAN (replace values!)
cat > server_ext.cnf <<'EOF'
subjectAltName=DNS:api.example.local,DNS:localhost,IP:127.0.0.1,IP:192.168.1.50
extendedKeyUsage=serverAuth
EOF

# CSR (CN is informational if SAN present)
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=MyOrg/CN=api.example.local"

# Sign with Intermediate CA
openssl x509 -req -in server.csr \
  -CA ../ca/intermediateCA.crt -CAkey ../ca/intermediateCA.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile server_ext.cnf
```

**Files to be used in Nginx:**

* `server.crt`, `server.key`
* **Chain for clients** (if full chain file is needed): `cat server.crt ../ca/intermediateCA.crt > server_fullchain.crt`


## 3) Create Client Certs (Per Device)

> Two practical strategies:
>
> * **A) Central generation (simple)** — generate key+cert and wrap in `.p12` (key leaves server; okay for test/pilots).
> * **B) On-device via MDM/SCEP (best practice)** — private key never leaves device (covered in Scaling section).

### 3.1 Central Generation (Simple + iOS-friendly .p12)

**Single Client (proof-of-concept):**

```bash
cd ../clients

# Client private key
openssl genrsa -out client1.key 2048

# Client CSR (CN can be device/user ID)
openssl req -new -key client1.key -out client1.csr \
  -subj "/C=US/ST=State/L=City/O=MyOrg/CN=device-001"

# Sign with Intermediate; EKU clientAuth
cat > client_ext.cnf <<'EOF'
extendedKeyUsage=clientAuth
EOF

openssl x509 -req -in client1.csr \
  -CA ../ca/intermediateCA.crt -CAkey ../ca/intermediateCA.key -CAcreateserial \
  -out client1.crt -days 365 -sha256 -extfile client_ext.cnf

# Export iOS-friendly PKCS#12 (IMPORTANT: legacy PBE + simple ASCII pwd)
openssl pkcs12 -export \
  -out client1_ios.p12 \
  -inkey client1.key -in client1.crt \
  -certfile ../ca/intermediateCA.crt \
  -passout pass:Test1234 \
  -macalg sha1 \
  -keypbe PBE-SHA1-3DES \
  -certpbe PBE-SHA1-3DES
```

**Batch 100–1000 Clients (`bash` Loop):**

```bash
# device list (one ID per line)
cat > devices.txt <<EOF
device-001
device-002
device-003
# ... add up to device-1000
EOF

mkdir -p out

while read DEV; do
  openssl genrsa -out ${DEV}.key 2048
  openssl req -new -key ${DEV}.key -out ${DEV}.csr -subj "/CN=${DEV}"
  openssl x509 -req -in ${DEV}.csr \
    -CA ../ca/intermediateCA.crt -CAkey ../ca/intermediateCA.key -CAcreateserial \
    -out ${DEV}.crt -days 365 -sha256 -extfile client_ext.cnf

  # Option: unique per-device password (record it!)
  PW="${DEV}1234"

  openssl pkcs12 -export \
    -out out/${DEV}.p12 \
    -inkey ${DEV}.key -in ${DEV}.crt \
    -certfile ../ca/intermediateCA.crt \
    -passout pass:${PW} \
    -macalg sha1 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES

  echo "${DEV},${PW}" >> out/p12_passwords.csv
done < devices.txt
```

**PowerShell `batch` (if needed):**

```powershell
$devices = @("device-001","device-002","device-003") # add more
New-Item -ItemType Directory -Force -Path out | Out-Null
"device,password" | Out-File out\p12_passwords.csv

foreach ($dev in $devices) {
  & openssl genrsa -out "$dev.key" 2048
  & openssl req -new -key "$dev.key" -out "$dev.csr" -subj "/CN=$dev"
  & openssl x509 -req -in "$dev.csr" `
    -CA ..\ca\intermediateCA.crt -CAkey ..\ca\intermediateCA.key -CAcreateserial `
    -out "$dev.crt" -days 365 -sha256 -extfile client_ext.cnf
  $pw = "$dev" + "1234"
  & openssl pkcs12 -export -out "out\$dev.p12" -inkey "$dev.key" -in "$dev.crt" `
    -certfile ..\ca\intermediateCA.crt -passout "pass:$pw" `
    -macalg sha1 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES
  "$dev,$pw" | Out-File -FilePath out\p12_passwords.csv -Append
}
```


## 4) Server (Nginx) mTLS Config

> Works the same on Linux or Windows (paths differ). Use **Intermediate CA** to validate clients.

**Linux-Style Paths (Edit Paths for Windows):**

```nginx
# mtls/nginx/nginx.conf
events {}
http {
  server {
    listen 443 ssl;
    server_name api.example.local localhost 192.168.1.50;

    # Server cert and key
    ssl_certificate     /path/to/mtls/server/server.crt;            # or server_fullchain.crt
    ssl_certificate_key /path/to/mtls/server/server.key;

    # Request & verify client certs signed by our Intermediate CA
    ssl_client_certificate /path/to/mtls/ca/intermediateCA.crt;
    ssl_verify_client on;                  # or "optional" if mixed traffic is needed
    ssl_verify_depth 2;

    # (Optional but recommended) Strong TLS
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # (Optional) CRL for client cert revocation (see Section 8)
    # ssl_crl /path/to/mtls/ca/intermediateCA.crl;

    # Simple test API
    location /api {
      default_type application/json;
      return 200 '{"status":"ok","message":"Hello mTLS!"}';
    }
  }
}
```

**Windows Paths Example:**

```
ssl_certificate     C:/mTLS/server/server.crt;
ssl_certificate_key C:/mTLS/server/server.key;
ssl_client_certificate C:/mTLS/ca/intermediateCA.crt;
# ssl_crl C:/mTLS/ca/intermediateCA.crl;
```

Note: Restart Nginx After Changes.


## 5) Install on iOS (Test Flow)

### 5.1 **Install Root CA** on Device and **Trust It**

* AirDrop or host `rootCA.crt`; open on iOS → Install.
* Settings → General → **About → Certificate Trust Settings** → enable trust for Root certificate.

### 5.2 **Install Client Identity (.p12)**

* AirDrop `device-001.p12` (or `client1_ios.p12`) → tap → enter its password (e.g., `device-0011234` or `Test1234`).
* It will show as an **Identity Certificate**.

### 5.3 **(Optional) Safari Test**

* Visit `https://api.example.local/api` (it should match SAN).
* Safari should prompt to select the identity.
* If all good, it should return `{"status":"ok","message":"Hello mTLS!"}`.

> For iOS, using a **real hostname** or the **exact IP in SAN** matters. Add both DNS and IP SANs as we did.


## 6) Test from Desktop Tools

### 6.1 `curl` (Linux/macOS)

```bash
curl -vk https://api.example.local/api \
  --cert clients/client1.crt --key clients/client1.key \
  --cacert ca/rootCA.crt
```

### 6.2 `curl` (Windows, schannel + P12)

```powershell
curl -vk https://api.example.local/api `
  --cert clients\out\device-001.p12:device-0011234 --cert-type P12 `
  --cacert ca\rootCA.crt
```

### 6.3 Python `requests`

```python
import requests

r = requests.get(
    "https://api.example.local/api",
    cert=("clients/client1.crt", "clients/client1.key"),
    verify="ca/rootCA.crt",
    timeout=10
)

print(r.status_code, r.text)
```

## 7) Scale to 100–1000 Devices (Distribution)

**Three Practical Tracks** (Choose One):

**A) MDM + SCEP (Best Practice, Scalable)**

* Stand up SCEP (Simple Certificate Enrollment Protocol) behind the Intermediate CA.
* Use MDM (Intune, Jamf, Kandji, etc.) to push:

  * **Root CA trust profile**.
  * **SCEP profile** to each device → device generates key **on device**, MDM obtains signed client cert automatically.
* Pros: keys never leave devices, easy renewal, one-click revocation.

**B) In-app Enrollment (no MDM)**

* Build an **enrollment endpoint** on the CA server:

  * App generates keypair in **iOS Keychain/Secure Enclave** → creates CSR → posts to `/enroll`.
  * Server signs CSR (clientAuth EKU) → returns `client.crt`.
  * App installs the cert **bound to the private key** in Keychain; URLSession uses that identity automatically (by specifying a `URLCredential` with identity).
* Pros: no MDM; key never leaves device.
* Cons: more engineering effort.

**C) Manual `.p12` Distribution (Pilot or Small Batches)**

* Use the **batch loop** above to make `N` `.p12` files and a `p12_passwords.csv`.
* Distribute via **Apple Configurator** / secure portal / AirDrop (not scalable long-term).


## 8) Revocation & Renewal

### 8.1 Create and Use a CRL (for Client Cert Revocation)

```bash
cd mtls/ca
# Create a fresh empty CRL index if there is no maintained one
# (In production, maintain a proper CA database; here’s a minimal path.)

# Mark a client cert as revoked (example uses the certificate file directly)
# First find its serial:
openssl x509 -in ../clients/client1.crt -noout -serial
# Revoke by serial (requires a CA database in a real CA setup)
# For a simple demo, reissue the CRL manually from a prebuilt index.txt
# Minimal CRL creation:
cat > ca_crl.cnf <<'EOF'
[ ca ]
default_ca = CA_default
[ CA_default ]
database = index.txt
private_key = intermediateCA.key
certificate = intermediateCA.crt
default_md = sha256
default_crl_days= 7
crlnumber = crlnumber
EOF

# Initialize CA db files for demo
touch index.txt
echo 1000 > crlnumber

# Issue CRL (demo—real CA flows mark revoked certs in index.txt)
openssl ca -gencrl -config ca_crl.cnf -out intermediateCA.crl
```

Add to Nginx and Reload:

```nginx
ssl_crl /path/to/mtls/ca/intermediateCA.crl;
```

> **Note:** Proper revocation needs a CA database (index.txt) that tracks issued serials, revocation dates, etc. For production, use an actual CA workflow (easyrsa, cfssl, step-ca, Smallstep, EJBCA, Microsoft ADCS, etc.), not raw ad-hoc files.

### 8.2 Renewal

* Issue short-lived client certs (90–365 days).
* For MDM/SCEP or In-app Enrollment, automate renewal before expiry.
* On the server, just keep trusting the same Intermediate CA.


## 9) Troubleshooting Quick Hits

* **“Hostname mismatch”**: ensure the **exact** hostname/IP used is in the **server SAN**.
* **iOS says “password incorrect” for .p12**: export with:

  ```
  -macalg sha1 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES
  ```

  and use a **simple ASCII** password.
* **Python fails verification**: pass `verify="ca/rootCA.crt"` and correct paths; ensure the CA used to sign the **server** is on the Root/Intermediate.
* **Server accepts without client cert**: ensure `ssl_verify_client on;` and it is pointing `ssl_client_certificate` to the **Intermediate CA** that issued client certs.
* **Check key–cert pair match**:

  ```bash
  openssl x509 -noout -modulus -in client1.crt | openssl md5
  openssl rsa  -noout -modulus -in client1.key | openssl md5
  ```

> Note: (hashes must match)


## 10) Minimal iOS App Snippet (Swift) for mTLS (Optional)

If decided to go with **In-app Enrollment** or to have the identity in Keychain, implement `URLSession` with client identity:

```swift
class MTLSDelegate: NSObject, URLSessionDelegate {
  func urlSession(_ session: URLSession,
                  didReceive challenge: URLAuthenticationChallenge,
                  completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

    let method = challenge.protectionSpace.authenticationMethod

    if method == NSURLAuthenticationMethodClientCertificate {
      // Retrieve identity + cert chain from keychain (added by profile or enrollment)
      var identity: SecIdentity?
      let query: [String: Any] = [
        kSecClass as String: kSecClassIdentity,
        kSecReturnRef as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
      ]
      var item: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &item)
      if status == errSecSuccess, let id = (item as? SecIdentity) {
        identity = id
        var cert: SecCertificate?
        SecIdentityCopyCertificate(id, &cert)
        let cred = URLCredential(identity: id, certificates: cert != nil ? [cert!] : [], persistence: .forSession)
        completionHandler(.useCredential, cred)
        return
      }
    }

    completionHandler(.performDefaultHandling, nil)
  }
}
```


## Summary

Above strategies can:

* Generate and manage a **Root + Intermediate CA**,
* Issue **server** and **client** certs,
* Package **iOS-friendly** `.p12`,
* **Enforce mTLS** on Nginx,
* **Install/trust** on iOS,
* **Test** with curl/Python,
* Plan **revocation/renewal** and **scale-out** via MDM/SCEP or in-app enrollment.


## Contribute

Share ideas, recommendations, and suggestions to:

- Contact: [RnD@security-science.com](mailto:RnD@security-science.com)
- Or [https://www.security-science.com/contact](https://www.security-science.com/contact)