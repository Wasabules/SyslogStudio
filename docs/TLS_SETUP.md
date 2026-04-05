# TLS Setup Guide

## Overview

Syslog messages are transmitted in plain text by default (UDP and TCP), which means they can be intercepted and read by anyone with access to the network. TLS (Transport Layer Security) encrypts the communication channel between syslog sources and SyslogStudio, ensuring confidentiality and integrity.

### When to Use TLS

- When syslog messages traverse untrusted networks (across VLANs, over the internet, through VPNs).
- When logs contain sensitive information (authentication events, security alerts, personally identifiable information).
- When compliance requirements mandate encrypted log transport (PCI DSS, HIPAA, SOC 2).
- When you want to authenticate the identity of the syslog server (preventing log injection to rogue collectors).

The standard port for syslog over TLS is **6514** (RFC 5425).

## Option 1: PKI Assistant (Recommended)

SyslogStudio includes a built-in PKI assistant that lets you generate a Certificate Authority (CA) and server certificates directly from the UI, with no command-line tools required.

### Step 1: Open the TLS Configuration

1. Click the **TLS Config** button in the server controls area.
2. The TLS configuration modal opens with two tabs: **PKI Assistant** and **Manual**.
3. Select the **PKI Assistant** tab.

### Step 2: Generate a CA Certificate

The CA (Certificate Authority) is the root of trust. Devices that trust this CA will accept any server certificate it signs.

1. In the PKI Assistant, locate the **Certificate Authority** section.
2. Configure the CA options:
   - **Algorithm**: Choose the key algorithm. Options are:
     - `ECDSA-P256` -- fast, modern, recommended for most use cases
     - `ECDSA-P384` -- stronger elliptic curve
     - `RSA-2048` -- widely compatible
     - `RSA-4096` -- maximum RSA strength
   - **Validity (days)**: How long the CA certificate is valid. Default is 3650 (10 years).
   - **Common Name**: A descriptive name for the CA (e.g., "My Syslog CA").
   - **Organization**: Your organization name.
3. Click **Generate CA**.
4. The CA certificate details are displayed, including subject, validity period, fingerprint, and algorithm.

### Step 3: Generate a Server Certificate

The server certificate identifies SyslogStudio to connecting devices. It must be signed by the CA you just created.

1. In the **Server Certificate** section of the PKI Assistant, configure:
   - **Algorithm**: Same options as the CA (can be different).
   - **Validity (days)**: How long the server certificate is valid. Default is 365 (1 year).
   - **Common Name**: A name for the server (e.g., "SyslogStudio Server").
   - **Organization**: Your organization name.
   - **DNS Names**: Hostnames that devices will use to connect. Always include `localhost` for local testing. Add your server's DNS name if applicable.
   - **IP Addresses**: IP addresses that devices will use to connect. Include `127.0.0.1` and `::1` for local testing, plus your server's actual IP address(es). The application can detect your local IPs to help populate this field.
2. Click **Generate Server Certificate**.
3. The server certificate details are displayed. Verify that the DNS Names and IP Addresses (SANs) are correct -- devices will reject the certificate if they connect using an address not listed in the SANs.

### Step 4: Export the CA Certificate

Devices need the CA certificate to verify the server's identity. Export it so you can distribute it.

1. Click **Export CA Certificate**.
2. Choose a save location in the file dialog. The default filename is `ca-cert.pem`.
3. This file contains only the CA's public certificate (no private key), so it is safe to distribute.

### Step 5: Enable TLS in Server Controls

1. Close the TLS configuration modal.
2. In the Server Controls, check the **TLS** checkbox.
3. The port defaults to 6514. Change it if needed.
4. Ensure **Use Self-Signed** is enabled (the PKI assistant uses in-memory certificates).
5. Click **Start**.
6. The TLS badge (e.g., `TLS:6514`) should appear, confirming the listener is active.

### Step 6: Configure Devices

On each device that sends syslog over TLS:

1. Copy the exported `ca-cert.pem` file to the device.
2. Configure the device's syslog client to:
   - Use TLS transport.
   - Connect to the SyslogStudio host on the configured TLS port (default 6514).
   - Trust the CA certificate by pointing to the `ca-cert.pem` file.

The exact configuration varies by device and syslog client. Here are examples for common tools:

**rsyslog:**

```
# /etc/rsyslog.d/tls-forward.conf
global(
  defaultNetstreamDriverCAFile="/path/to/ca-cert.pem"
)

action(
  type="omfwd"
  target="192.168.1.100"
  port="6514"
  protocol="tcp"
  streamDriver="gtls"
  streamDriverMode="1"
  streamDriverAuthMode="x509/name"
)
```

**syslog-ng:**

```
destination d_tls {
  syslog("192.168.1.100"
    port(6514)
    transport("tls")
    tls(
      ca-file("/path/to/ca-cert.pem")
    )
  );
};
```

## Option 2: Manual (Load Existing Certificates)

If you already have TLS certificates (for example, from your organization's PKI, Let's Encrypt, or generated with OpenSSL), you can load them directly.

### Certificate and Key File Formats

SyslogStudio expects certificates and keys in **PEM format**. PEM files are base64-encoded and look like this:

```
-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQC7... (base64 data)
-----END CERTIFICATE-----
```

```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkq... (base64 data)
-----END PRIVATE KEY-----
```

Supported private key types:

- `RSA PRIVATE KEY` (PKCS#1)
- `EC PRIVATE KEY` (SEC 1)
- `PRIVATE KEY` (PKCS#8, works for both RSA and ECDSA)

If your certificates are in a different format (DER, PFX/PKCS#12), convert them to PEM first using OpenSSL:

```bash
# DER to PEM (certificate)
openssl x509 -inform der -in cert.der -out cert.pem

# DER to PEM (key)
openssl rsa -inform der -in key.der -out key.pem

# PFX/PKCS#12 to PEM
openssl pkcs12 -in cert.pfx -out cert.pem -clcerts -nokeys
openssl pkcs12 -in cert.pfx -out key.pem -nocerts -nodes
```

### Loading Certificates

1. Click **TLS Config** in the server controls.
2. Select the **Manual** tab.
3. Click **Browse** next to the Certificate field and select your `.pem` or `.crt` file.
4. Click **Browse** next to the Private Key field and select your `.pem` or `.key` file.
5. Close the modal.
6. In the Server Controls, enable **TLS** and make sure **Use Self-Signed** is unchecked (since you are providing your own files).
7. Click **Start**.

## Mutual TLS (mTLS)

Standard TLS only authenticates the server to the client. Mutual TLS (mTLS) adds client authentication: the server also verifies the client's certificate. This ensures that only authorized devices can send logs to SyslogStudio.

### When to Use mTLS

- When you want to restrict which devices can send logs (zero-trust environments).
- When compliance requires mutual authentication.
- When the syslog server is exposed to a broad network and you need access control.

### Configuring mTLS

1. Ensure you have a CA certificate that was used to sign your clients' certificates. This can be:
   - The same CA you generated with the PKI assistant (if you also use it to sign client certs).
   - A separate CA that your organization uses for device certificates.
2. Open **TLS Config**.
3. Enable the **Mutual TLS** option.
4. Click **Browse** next to the CA Certificate field and select the CA certificate file that signed your client certificates.
5. Close the modal and start the server with TLS enabled.

When mTLS is active, any client that connects must present a valid certificate signed by the specified CA. Connections without a valid client certificate are rejected.

### Preparing Client Certificates

Each syslog-sending device needs:

1. A client certificate signed by the CA you configured for mTLS.
2. The corresponding private key.
3. The server's CA certificate (to verify the server, just like standard TLS).

Generate client certificates using your organization's PKI tools or OpenSSL:

```bash
# Generate client key
openssl genrsa -out client-key.pem 2048

# Generate CSR
openssl req -new -key client-key.pem -out client.csr -subj "/CN=my-device/O=MyOrg"

# Sign with your CA
openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out client-cert.pem -days 365
```

Configure the syslog client on each device to present `client-cert.pem` and `client-key.pem` during the TLS handshake.

## Troubleshooting

### "TLS certificate file not found" or "TLS key file not found"

The file path specified for the certificate or key does not exist or is not accessible. Verify:

- The file path is correct and the file exists.
- The application has read permissions for the file.
- You have not moved or renamed the file since selecting it.

### "Failed to load certificate" or "Failed to create TLS certificate"

The certificate and key files exist but cannot be parsed. Common causes:

- The certificate and key do not match (they were generated separately or belong to different certificates).
- The files are not in PEM format. Convert them as described above.
- The PEM file is corrupted or truncated.

To verify a certificate and key match:

```bash
# These two commands should output the same modulus
openssl x509 -noout -modulus -in cert.pem | openssl md5
openssl rsa -noout -modulus -in key.pem | openssl md5
```

### "No CA certificate available; generate a CA first"

You tried to generate a server certificate signed by a CA, but no CA has been generated yet. Go to the PKI Assistant and generate a CA certificate first (Step 2 above).

### Clients cannot connect or get "certificate verify failed"

- Ensure the CA certificate has been distributed to the client device and is configured correctly.
- Verify that the server certificate's SAN (Subject Alternative Name) entries include the hostname or IP address the client is using to connect. If a client connects to `192.168.1.100` but the certificate only lists `localhost`, the connection will be rejected.
- Check that the server certificate has not expired. Certificate details are shown in the TLS Config modal.
- If using mTLS, ensure the client has a valid certificate signed by the CA configured on the server.

### "Connection refused" on port 6514

- Verify that TLS is enabled and the server is running (the TLS badge should be visible).
- Check that no firewall is blocking the port.
- Confirm the port number matches on both the server and client configuration.

### Performance Considerations

TLS adds encryption overhead. In most environments this is negligible, but if you are receiving tens of thousands of messages per second, you may notice higher CPU usage compared to plain UDP/TCP. ECDSA certificates (P-256) are generally faster for TLS handshakes than RSA certificates.
