# Basic mTLS (Mutual TLS) Implementation


## How it Works in mTLS Trust:

* **Both certs are signed by the same CA**
  or
* Both certs are signed by **different CAs**, but each side has the **other CA's root (or intermediate) certificate** in its trust store.

1. **Server Validation**: 

   * The client verifies the **server’s certificate chain** using the **CA(s)** it trusts.
   * If the server’s cert isn’t signed by a trusted CA → handshake fails.

2. **Client Validation**:

   * The server verifies the **client’s certificate chain** using the **CA(s)** it’s configured to trust (`ssl_client_certificate` in Nginx, `client_ca_list` in Apache, etc.).
   * If the client’s cert isn’t signed by a trusted CA → handshake fails.

✅ **Same CA scenario** (Simplest)

```
CA.crt
├── server.crt (signed by CA)
└── client.crt (signed by CA)
```

Both sides only need to trust `CA.crt`.

✅ **Different CA scenario**

```
CA_Server.crt  → trusts server certs
CA_Client.crt  → trusts client certs
```

* Server must trust `CA_Client.crt`
* Client must trust `CA_Server.crt`


❌ **Self-signed certs without sharing CA**

* If each side has its own self-signed cert and they don’t exchange & trust each other’s cert/CA, mTLS won’t work.


## 1) High-level Requirements

* A **Private CA** (for test/dev) or a CA under developer's control (production: managed PKI like Vault/ACM Private CA).
* A **Server certificate** signed by that CA (EKU = `serverAuth`, SAN contains developer's server name).
* **Client certificate(s)** signed by the same CA (EKU = `clientAuth`). For iOS testing, usually a `.p12` bundle (cert + private key) needs to be created.
* Server that **requires** client certs (Nginx/Envoy/Node/etc).
* Tools: `openssl`, `nginx` (or Node), `curl`, Xcode (for iOS app), an iOS device (simulator ok for handshake logic — physical device needed to test hardware-backed key storage).
* For production: certificate issuance/rotation/provisioning system (API + device attestation) must be in-placed so a developer don’t embed a single client key in the app.


## 2) Create CA, Server Cert, Client Cert (using OpenSSL)

Create a directory `mTLS` and run these commands there.

**1. Create a root CA**

```bash
# CA private key
openssl genrsa -out ca.key 4096

# CA self-signed cert
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -out ca.crt \
  -subj "/C=US/ST=State/L=City/O=MyTestCA/OU=Dev/CN=MyTestRootCA"
```

**2. Create Server Key & CSR and Sign Server Cert it with CA**
Create `server_ext.cnf` with:

```
subjectAltName = DNS:api.example.local, IP:127.0.0.1
extendedKeyUsage = serverAuth
keyUsage = digitalSignature, keyEncipherment
```

Commands:

```bash
# Create Server Key
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=MyOrg/CN=api.example.local"

# Create Server CSR
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile server_ext.cnf
```

(OR) Create Subject Alternative Name (SAN) `server_SAN.cnf` with:

```
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
C  = US
ST = TestState
L  = TestCity
O  = TestOrg
OU = TestUnit
CN = localhost

[ req_ext ]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1   = localhost
IP.1    = 127.0.0.1
```

Commands:

```bash
# SAN-Based
# Create Server CSR
openssl req -new -key server.key -out server.csr -config server_SAN.cnf

# Sign Server Certificate
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256 \
  -extfile server_SAN.cnf -extensions req_ext
```

**3. Create Client Key & CSR and Sign Client Cert it with CA**

Create `client_ext.cnf` with:

```
extendedKeyUsage = clientAuth
subjectAltName = email:client1@example.local
```

Commands:

```bash
# Create Client Key
openssl genrsa -out client.key 2048

# Create Client CSR
openssl req -new -key client.key -out client.csr \
  -subj "/C=US/ST=State/L=City/O=MyOrg/OU=Clients/CN=client1"

# Sign Client Certificate
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 -sha256 -extfile client_ext.cnf
```

(OR) Create Subject Alternative Name (SAN) `client_SAN.cnf` with:
```
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
C  = US
ST = State
L  = City
O  = MyOrg
OU = IT
CN = test-client

[ req_ext ]
extendedKeyUsage = clientAuth
```

Commands:

```bash
# SAN-Based
# Create Client CSR
openssl req -new -key client.key -out client.csr -config client_SAN.cnf

# Sign Client Certificate
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365 -sha256 \
  -extfile client_SAN.cnf -extensions req_ext
```

**4. Create a PKCS#12 bundle for iOS (.p12)**

```bash
openssl pkcs12 -export \
  -out client.p12 \
  -inkey client.key \
  -in client.crt \
  -certfile ca.crt \
  -passout pass:MyP12Passw0rd

# (OR) Exporting the .p12 using explicit legacy algorithms compatible with iOS  
openssl pkcs12 -export \
  -out client_ios.p12 \
  -inkey client.key \
  -in client.crt \
  -certfile ca.crt \
  -passout pass:MyP12Passw0rd \
  -macalg sha1 \
  -keypbe PBE-SHA1-3DES \
  -certpbe PBE-SHA1-3DES
```

Created the following: `ca.crt`, `server.key`, `server.crt`, `client.crt`, `client.key`, `client.p12`.


## 3) Install Nginx (Windows)

### **1. Download Nginx for Windows**

* Go to the official site:
  [https://nginx.org/en/download.html](https://nginx.org/en/download.html)
* Under **Stable version**, download the **Windows zip** (e.g., `nginx-1.xx.x.zip`).

### **2. Extract Nginx**

* Unzip to a folder, for example:

  ```
  C:\nginx
  ```
  
* Inside are as follows:

  ```
  C:\nginx\nginx.exe
  C:\nginx\conf\nginx.conf
  C:\nginx\html\
  ```


## 4) Server Setup — Nginx (TLS Termination + Require Client Certs) + Backend Example

**A. Nginx Config (Terminate TLS, Require Client Certs, Forward Client Cert to Backend):**

```nginx
server {
    listen 443 ssl;
    server_name api.example.local;

    ssl_certificate /path_to/mTLS/server.crt;
    ssl_certificate_key /path_to/mTLS/server.key;
    ssl_client_certificate /path_to/mTLS/ca.crt;   ## trust this CA for clients
    ssl_verify_client on;          ## require client cert
    ssl_verify_depth 2;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    location / {
        return 200 "Hello, mTLS client!\n";
        ## forward cert to backend if a developers want the app logic to inspect fields
        # proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
        # proxy_pass http://127.0.0.1:3000;
    }
}
```

Place `server.crt`, `server.key`, `ca.crt` in `/path_to/mTLS/`.

**B. Start Nginx**

Open **Command Prompt** or **PowerShell** in:

```
C:\nginx
```

Run:

```powershell
nginx
```

To stop:

```powershell
nginx -s stop
```

To reload after config change:

```powershell
nginx -s reload
```

**C. Simple Node HTTPS server that enforces client certs (no Nginx)**

```js
// save to server.js
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.crt'),
  ca: fs.readFileSync('ca.crt'),
  requestCert: true,
  rejectUnauthorized: true  // will only accept clients signed by CA
};

https.createServer(options, (req, res) => {
  const cert = req.socket.getPeerCertificate(true);
  if (!req.client.authorized) {
    res.writeHead(401);
    res.end('Client certificate required or invalid');
    return;
  }
  // client is authorized — a developer can inspect cert.subject, cert.issuer, etc.
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end(`Hello ${cert.subject.CN || 'client'}\n`);
}).listen(8443, () => console.log('mTLS server listening on 8443'));
```

Run it with: `node server.js`

**D. Testing Server with `curl`**

```bash
## using cert+key files
curl --cacert ca.crt --cert client.crt --key client.key https://localhost:443/

## using p12 (if openssl compiled curl supports it)
curl --cacert ca.crt --cert client.p12:MyP12Passw0rd --cert-type P12 https://localhost:443/
```

** E. Testing with Python

```python
import requests

url = "https://localhost/api"

response = requests.get(
    url,
    cert=("/path/to/client.crt",
          "/path/to/client.key"),
    verify="/path/to/ca.crt"
)

print("Status:", response.status_code)
print("Body:", response.text)
```


## 5) iOS — Installing the CA and Client Certificate on Device (Manual Steps)

### A. Install Root CA (`ca.crt`)

1. Host `ca.crt` on a local web server (or email it).
2. On iOS device open Safari and open the `ca.crt` URL.
3. iOS will prompt to install a profile — follow the prompts to install.
4. After install, enable full trust: `Settings → General → About → Certificate Trust Settings` → toggle the Root CA to **ON**.

> Simulator: open Safari in the simulator and browse to the CA URL and tap to install. Note: Simulator stores certs per-sim and doesn't have Secure Enclave.

### B. Install the Client PKCS#12 (`client.p12`)

1. Host `client.p12` (or AirDrop it to the device).
2. Tap the `client.p12` file on the device → install — enter the PKCS#12 password (e.g., `MyP12Passw0rd`).
3. Confirm installation. The identity will appear as an installed profile (Settings → General → VPN & Device Management → Profiles).

**Important:** If a developer plans to do automated provisioning, prefer generating private key on device + CSR (recommended). Installing a `.p12` imports private key into Keychain (not ideal for scaling; ok for testing).


## 6) iOS Sample App (Swift) — import or use installed identity + perform mTLS request

This Swift code demonstrates:

* importing a local `client.p12` file programmatically (optional),
* storing/using identity,
* responding to `NSURLAuthenticationMethodClientCertificate` challenge.

> For production prefer key generation on-device + CSR. For testing, we show PKCS#12 import.

**A. Helper: import PKCS#12 and extract identity**

```swift
import Foundation
import Security

func identityAndCertsFromPKCS12(p12Data: Data, passphrase: String) -> (SecIdentity, [SecCertificate])? {
    let options = [kSecImportExportPassphrase as String: passphrase]
    var items: CFArray?
    let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
    guard status == errSecSuccess,
          let array = items as? [[String: Any]],
          let dict = array.first,
          let identity = dict[kSecImportItemIdentity as String] as? SecIdentity else {
        return nil
    }

    var certs: [SecCertificate] = []
    if let certChain = dict[kSecImportItemCertChain as String] as? [SecCertificate] {
        certs = certChain
    }
    return (identity, certs)
}
```

**B. URLSessionDelegate that supplies client identity when asked**

```swift
import Foundation
import Security

class MTLSDelegate: NSObject, URLSessionDelegate {
    var identity: SecIdentity?
    var certs: [SecCertificate]?

    init(identity: SecIdentity?, certs: [SecCertificate]?) {
        self.identity = identity
        self.certs = certs
    }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

        // Client certificate requested
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
            guard let identity = self.identity else {
                completionHandler(.rejectProtectionSpace, nil)
                return
            }

            let certsArray = self.certs as CFArray?
            let credential = URLCredential(identity: identity, certificates: certsArray as? [Any], persistence: .forSession)
            completionHandler(.useCredential, credential)
            return
        }

        // Default handling for server trust (a developer can pin here)
        completionHandler(.performDefaultHandling, nil)
    }
}
```

**C. Example usage (load p12 bundled in app for quick test)**

```swift
// inside a ViewController or AppDelegate (for test only bundle client.p12 in app resources)
guard let p12url = Bundle.main.url(forResource: "client", withExtension: "p12"),
      let p12data = try? Data(contentsOf: p12url),
      let (identity, certs) = identityAndCertsFromPKCS12(p12Data: p12data, passphrase: "MyP12Passw0rd") else {
    print("Failed to load p12")
    return
}

let delegate = MTLSDelegate(identity: identity, certs: certs)
let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: .main)

// call developer server (if using nginx termination on 443)
let url = URL(string: "https://api.example.local/")!
let task = session.dataTask(with: url) { data, resp, err in
    if let err = err { print("request error:", err) ; return }
    print("response:", String(data: data ?? Data(), encoding: .utf8) ?? "")
}
task.resume()
```

**Notes:**

* If the developer installed `.p12` into the system Keychain (via Settings), the developer can find the identity via a Keychain query (search `kSecClassIdentity` with attributes).
* If the server uses a test CA, make sure the CA is trusted on the device (installed as root CA). Otherwise iOS will block the connection (unless the developer creates ATS exceptions — not recommended).


## 7) Testing & Troubleshooting Checklist

* `curl` from desktop: verify server accepts the client certs.

  * `curl --cacert ca.crt --cert client.crt --key client.key https://localhost:443/`
* On Nginx test, check `$ssl_client_verify` variable (can print in logs) and `$ssl_client_s_dn` to inspect DNs.
* iOS:
  * Ensure CA root appears in `Settings → General → About → Certificate Trust Settings`.
  * If using simulator: import CA into simulator and install `.p12` to simulator.
  * For real device: watch device logs in Console.app; see network connection rejections in the system logs.
* If iOS says “untrusted certificate”: CA not trusted or wrong SAN (hostname mismatch).
* If server rejects client: server’s trust store doesn’t contain developer's CA or Nginx/Node not configured to require client certs.
* For detailed server-side certificate info in Node: `req.socket.getPeerCertificate(true)`.
* Mismatched key and cert
   * The private key (`client.key`) must exactly match the certificate (`client.crt`) inside `.p12`.
   * Verify with:
  
     ```bash
     openssl x509 -noout -modulus -in client.crt | openssl md5
     openssl rsa -noout -modulus -in client.key | openssl md5
     ```
     
   The MD5 hashes must be identical.  
* Verify `.p12` file structure**
   * Confirm the `.p12` actually includes **both** the client cert and the private key:

     ```bash
     openssl pkcs12 -info -in client.p12 -noout -password pass:MyP12Passw0rd
     ```

     It should list private key and certificates.
* Check the `.p12` contents:
  * The `.p12` **must contain both**:
    * The **client certificate** (`client.crt`)
    * The **matching private key** (`client.key`)
    * (Optionally) the CA chain

      ```bash
      openssl pkcs12 -info -in client.p12
      ```

## 8) Production Considerations / Hardening

* **Do not embed a shared `.p12`** in distributed apps — generate per-device certs.
* **Best**: generate key pair on device (SecKeyCreateRandomKey), create CSR on device, send CSR over authenticated channel to CA signing endpoint, receive client cert — private key never leaves device.
* **Short-lived certs** (hours/days) reduce need for revocation checks. Rotate frequently.
* For revocation: use OCSP checks on server or rely on short-lived certs.
* Use **Device attestation** (Apple DeviceCheck / App Attest) or MDM for high assurance during provisioning.
* Pin server certificate in app (certificate or public key pinning) to avoid rogue TLS interception.
* Log client cert DN and failures for audits.
* Restrict accepted client certs via EKU + SAN + subject DN checks at application level when necessary.


## 9) Quick Android Note (if a developer wants parity)

* Use hardware-backed Keystore (if available). Generate keypair on device and produce CSR to server for signing.
* Example of creating `SSLContext` with PKCS12:

```java
KeyStore keyStore = KeyStore.getInstance("PKCS12");
try (InputStream is = ... /* client.p12 */) {
  keyStore.load(is, "MyP12Passw0rd".toCharArray());
}
KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
kmf.init(keyStore, "MyP12Passw0rd".toCharArray());
SSLContext context = SSLContext.getInstance("TLS");
context.init(kmf.getKeyManagers(), null, null);
OkHttpClient client = new OkHttpClient.Builder()
  .sslSocketFactory(context.getSocketFactory(), (X509TrustManager)trustManager)
  .build();
```

## Contribute

Share ideas, recommendations, and suggestions to:

- Contact: [RnD@security-science.com](mailto:RnD@security-science.com)
- Or [https://www.security-science.com/contact](https://www.security-science.com/contact)