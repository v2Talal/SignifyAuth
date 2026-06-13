# SignifyAuth

**Zero-knowledge passwordless authentication system. No passwords. No emails. Just your key.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

SignifyAuth replaces passwords and emails with **Ed25519 digital signatures**. Users authenticate by proving they possess a private key. The website never sees, stores, or transmits the key. A **two-signature protocol** ensures both identity verification and session integrity.

---

## Table of Contents

- [What Is This?](#what-is-this)
- [How It Works](#how-it-works)
- [The Two-Signature Protocol](#the-two-signature-protocol)
- [Security Model](#security-model)
- [Quick Start (Localhost)](#quick-start-localhost)
- [Deployment on VPS (Production)](#deployment-on-vps-production)
- [Project Structure](#project-structure)
- [Server API Reference](#server-api-reference)
- [JavaScript SDK](#javascript-sdk)
- [Browser Extension](#browser-extension)
- [Integrating Into Any Website](#integrating-into-any-website)
- [Cryptographic Details](#cryptographic-details)
- [Security Hardening](#security-hardening)
- [FAQ](#faq)
- [License](#license)

---

## What Is This?

SignifyAuth is a complete passwordless authentication system that works with any website. It consists of three parts:

| Component | Purpose |
|-----------|---------|
| **Server** | Stores public keys, issues challenges, verifies signatures |
| **Browser Extension** | Manages encrypted private keys, signs challenges on user request |
| **JavaScript SDK** | Drop-in library for any website to integrate SignifyAuth |

**The core idea:** Instead of "proving you know a secret" (password), you "prove you have a key" (digital signature). The private key never leaves your device. The server only knows your public key.

---

## How It Works

### Registration (One Time)

```
User                    Extension                    Server
 │                          │                           │
 │  Click "Create ID"       │                           │
 │─────────────────────────▶│                           │
 │                          │  Generate Ed25519 pair    │
 │                          │  Encrypt private key      │
 │                          │  with user's password     │
 │                          │                           │
 │                          │  Send public key          │
 │                          │──────────────────────────▶│
 │                          │                           │  Store {userId, publicKey}
 │                          │◀──────────────────────────│
 │  Done! Key saved locally │                           │
 │◀─────────────────────────│                           │
```

**What the server stores:** `{ userId, publicKey, username }`
**What the server never sees:** The private key, the password

### Login (Every Time)

```
User                    Extension                    Server
 │                          │                           │
 │  Click "Log In"          │                           │
 │─────────────────────────▶│                           │
 │                          │                           │
 │  1. Select account       │  Request challenge        │
 │  2. Enter password       │──────────────────────────▶│
 │                          │◀──── { challenge } ───────│
 │                          │                           │
 │  3. Sign challenge       │                           │
 │     (1st signature)      │                           │
 │                          │  Verify identity          │
 │                          │──────────────────────────▶│
 │                          │◀── { confirmChallenge } ──│
 │                          │                           │
 │  4. Sign confirmation    │                           │
 │     (2nd signature)      │                           │
 │                          │  Verify confirmation      │
 │                          │──────────────────────────▶│
 │                          │◀──── { sessionToken } ────│
 │  ✓ Logged in!            │                           │
 │◀─────────────────────────│                           │
```

---

## The Two-Signature Protocol

The core innovation is **two separate cryptographic signatures** per login:

| Step | What is Signed | What It Proves |
|------|---------------|----------------|
| **1st Signature** | Random 32-byte challenge from server | "I own this private key" |
| **2nd Signature** | Confirmation challenge from server | "I am still present and this session is genuine" |

### Why Two Signatures?

1. **Identity verification (1st):** Proves the user possesses the private key
2. **Session confirmation (2nd):** Proves the user is actively present and prevents replay attacks
3. **Session binding:** Each challenge is unique and tied to a specific session ID
4. **Anti-replay:** Challenges expire after 5 minutes and can only be used once

---

## Security Model

### What's Protected

| Threat | Protection |
|--------|-----------|
| **Password guessing** | No passwords exist |
| **Database breach** | Only public keys are stored |
| **Phishing** | Challenges are site-specific and time-limited |
| **Replay attacks** | Each challenge is unique and single-use |
| **Key theft** | Private keys are encrypted at rest (AES-256-GCM + PBKDF2) |
| **Memory extraction** | Private key exists in memory only during signing (~1ms) |
| **Man-in-the-middle** | Signatures are bound to specific challenges |

### Encryption at Rest

Private keys are **never** stored in plaintext:

```
User's Password
    │
    ▼
PBKDF2 (600,000 iterations, SHA-256)
    │
    ▼
AES-256-GCM Key
    │
    ▼
Private Key ──encrypted──▶ Stored Blob (chrome.storage)
```

- **600,000 PBKDF2 iterations** — brute-force resistant
- **AES-256-GCM** — authenticated encryption (tamper-proof)
- **Random salt (32 bytes) + IV (12 bytes)** per encryption
- **Auto-wipe** — decrypted key cleared after 30 seconds or immediately after signing

### What the Server Never Knows

- Your private key
- Your password
- Any secret that could impersonate you

### What Happens If You Lose Your Key

- You cannot log in again — no recovery possible
- The website cannot help you — they don't have your key
- Even the website owner cannot access your account
- This is by design — it's the price of true zero-knowledge security

---

## Quick Start (Localhost)

### Step 1: Clone and Install

```bash
git clone https://github.com/yourusername/signifyauth.git
cd signifyauth

# Install server dependencies
cd server
npm install
cd ..
```

### Step 2: Start the Server

```bash
cd server
npm start
```

You'll see:
```
🔐 SignifyAuth Server running on http://localhost:3000
📡 API endpoints:
   POST /api/register            - Register with public key
   POST /api/challenge            - Request login challenge
   POST /api/verify-identity      - Step 1: Identity signature
   POST /api/verify-confirmation  - Step 2: Session confirmation
   POST /api/verify-session       - Check session validity
   POST /api/logout               - End session
```

### Step 3: Load the Chrome Extension

1. Open `chrome://extensions`
2. Enable **Developer Mode** (top right toggle)
3. Click **"Load unpacked"**
4. Select the `extension/` folder from this project
5. The SignifyAuth icon appears in your toolbar

### Step 4: Test the Complete Flow

1. Open `http://localhost:3000`
2. Click **"Create Identity"** → extension opens → create a key with password
3. Click **"Log In"** → extension opens → select account → enter password → sign
4. You're logged in!

---

## Deployment on VPS (Production)

### Prerequisites

- A VPS running Ubuntu 20.04+ (DigitalOcean, Vultr, AWS, etc.)
- Node.js 18+ installed
- Nginx installed
- A domain name pointed to your VPS IP
- SSL certificate (Let's Encrypt)

### Step 1: Server Setup

```bash
# Connect to your VPS
ssh root@your-server-ip

# Update system
apt update && apt upgrade -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

# Install Nginx
apt install -y nginx

# Install PM2 (process manager)
npm install -g pm2
```

### Step 2: Deploy the Server

```bash
# Create project directory
mkdir -p /var/www/signifyauth
cd /var/www/signifyauth

# Clone the repository
git clone https://github.com/yourusername/signifyauth.git .

# Install dependencies
cd server
npm install

# Start with PM2
pm2 start server.js --name signifyauth
pm2 save
pm2 startup
```

### Step 3: Configure Nginx

```bash
# Create Nginx config
nano /etc/nginx/sites-available/signifyauth
```

Add this configuration:

```nginx
server {
    listen 80;
    server_name auth.yourdomain.com;

    # Redirect HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;

    # SSL (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline';" always;

    # Proxy to Node.js
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;
    location /api/ {
        limit_req zone=api burst=10 nodelay;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
# Enable the site
ln -s /etc/nginx/sites-available/signifyauth /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

### Step 4: SSL Certificate

```bash
# Install Certbot
apt install -y certbot python3-certbot-nginx

# Get SSL certificate
certbot --nginx -d auth.yourdomain.com

# Auto-renewal
certbot renew --dry-run
```

### Step 5: Update SDK Server URL

In your website, update the SDK to point to your production server:

```javascript
var auth = new SignifyAuth({
    serverUrl: 'https://auth.yourdomain.com'
});
```

### Step 6: Update Extension Host Permissions

In `extension/manifest.json`, add your production domain:

```json
{
    "host_permissions": [
        "http://localhost:3000/*",
        "http://127.0.0.1:3000/*",
        "https://auth.yourdomain.com/*"
    ]
}
```

### Step 7: Restart the Server

```bash
pm2 restart signifyauth
```

---

## Project Structure

```
signifyauth/
├── server/                          # Express API server
│   ├── server.js                    # Main server with all endpoints
│   ├── package.json                 # Dependencies
│   └── package-lock.json
│
├── sdk/                             # Drop-in JavaScript SDK
│   └── signifyauth.js               # Works in any browser
│
├── extension/                       # Chrome Extension (Manifest V3)
│   ├── manifest.json                # Extension configuration
│   ├── popup/
│   │   ├── popup.html               # Extension popup UI
│   │   └── popup.js                 # Key management, signing, backup/import
│   ├── content/
│   │   ├── content.js               # Bridge between website and extension
│   │   └── content.css              # Floating notification indicator
│   ├── background/
│   │   └── service-worker.js        # Message routing, port management
│   ├── lib/
│   │   └── tweetnacl.js             # Ed25519 cryptography library
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
│
├── demo-site/                       # Interactive demo website
│   ├── index.html                   # Full demo with registration and login
│   ├── app.js                       # Client logic with extension integration
│   └── style.css                    # Dark theme, responsive design
│
├── .gitignore                       # Git ignore rules
├── package.json                     # Root configuration
└── README.md                        # This file
```

---

## Server API Reference

### Base URL

```
http://localhost:3000          (local)
https://auth.yourdomain.com   (production)
```

### POST `/api/register`

Register a new identity with a public key.

**Request:**
```json
{
  "publicKey": "base64-encoded-ed25519-public-key",
  "username": "alice"
}
```

**Response (200):**
```json
{
  "userId": "uuid",
  "message": "Registration successful"
}
```

**Errors:**
- `400` — Invalid public key format
- `429` — Rate limit exceeded (10 requests/minute)

---

### POST `/api/challenge`

Request a login challenge for a specific public key.

**Request:**
```json
{
  "publicKey": "base64-encoded-ed25519-public-key"
}
```

**Response (200):**
```json
{
  "sessionId": "uuid",
  "challenge": "base64-random-32-bytes",
  "nonce": "hex-random-16-bytes",
  "timestamp": 1234567890,
  "step": "identity"
}
```

**Errors:**
- `404` — User not found (public key not registered)
- `429` — Rate limit exceeded (30 requests/minute)

---

### POST `/api/verify-identity`

Step 1: Verify the identity signature.

**Request:**
```json
{
  "sessionId": "uuid",
  "signature": "base64-encoded-ed25519-signature",
  "publicKey": "base64-encoded-ed25519-public-key"
}
```

**Response (200):**
```json
{
  "sessionId": "uuid",
  "confirmationChallenge": "base64-random-32-bytes",
  "step": "confirmation"
}
```

**Errors:**
- `400` — Invalid or expired challenge
- `401` — Invalid signature
- `400` — Public key mismatch

---

### POST `/api/verify-confirmation`

Step 2: Verify the session confirmation signature.

**Request:**
```json
{
  "sessionId": "uuid",
  "signature": "base64-encoded-ed25519-signature",
  "publicKey": "base64-encoded-ed25519-public-key"
}
```

**Response (200):**
```json
{
  "success": true,
  "sessionToken": "uuid",
  "userId": "uuid",
  "username": "alice"
}
```

**Errors:**
- `400` — Invalid or expired challenge
- `401` — Invalid confirmation signature
- `400` — Challenge already used (replay attempt)

---

### POST `/api/verify-session`

Check if a session is valid.

**Request:**
```json
{
  "sessionToken": "uuid"
}
```

**Response (200):**
```json
{
  "valid": true,
  "userId": "uuid",
  "username": "alice"
}
```

---

### POST `/api/logout`

End a session.

**Request:**
```json
{
  "sessionToken": "uuid"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Logged out"
}
```

---

## JavaScript SDK

The SDK works in any browser without the extension. It handles key generation, signing, and server communication.

### Installation

```html
<script src="https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl-fast.min.js"></script>
<script src="/sdk/signifyauth.js"></script>
```

Or host it yourself:

```html
<script src="https://your-cdn.com/tweetnacl.min.js"></script>
<script src="https://your-cdn.com/signifyauth.js"></script>
```

### Initialize

```javascript
var auth = new SignifyAuth({
    serverUrl: 'https://auth.yourdomain.com',
    siteName: 'My Website'  // optional, defaults to document.title
});
```

### Register (Generate Keys)

```javascript
auth.register('alice').then(function (result) {
    console.log('User ID:', result.userId);
    console.log('Public Key:', result.publicKey);
    console.log('Private Key:', result.keyPair.secretKey);
    // IMPORTANT: Save the private key securely!
});
```

### Login (Direct — Private Key in Code)

```javascript
auth.login(secretKeyBase64).then(function (session) {
    console.log('Logged in as:', session.username);
    console.log('Session token:', session.sessionToken);
});
```

### Login (Via Extension — Recommended)

```javascript
auth.loginWithExtension(publicKey).then(function (session) {
    console.log('Logged in via extension:', session.username);
});
```

### Verify Session

```javascript
auth.verifySession(sessionToken).then(function (result) {
    if (result.valid) {
        console.log('Session valid for:', result.username);
    }
});
```

### Logout

```javascript
auth.logout(sessionToken).then(function () {
    console.log('Logged out');
});
```

---

## Browser Extension

### Features

| Feature | Description |
|---------|-------------|
| **Encrypted key storage** | AES-256-GCM with PBKDF2 (600K iterations) |
| **Password-protected signing** | Every signature requires password entry |
| **Auto-wipe** | Private key cleared from memory after 30 seconds |
| **Multi-key support** | Manage multiple identities |
| **Account selection** | Choose which account to sign with |
| **Backup/Import** | Encrypted `.Signify` backup files |
| **Key import/export** | Transfer keys between devices |
| **Two-signature support** | Handles both identity and confirmation steps |
| **Floating notifications** | Visual indicator when action is needed |

### How the Extension Works

1. Website sends a sign request via `postMessage`
2. Content script relays to the extension background
3. Background opens the popup and shows account selection
4. User selects account and enters password
5. Extension decrypts the private key, signs the challenge
6. Extension signs the confirmation challenge automatically
7. Both signatures are sent back to the website
8. Private key is immediately wiped from memory

### Key Management

- **Create:** Generate a new Ed25519 key pair, encrypted with your password
- **Import:** Paste an existing private key, set a password to encrypt it
- **View:** Enter password to temporarily decrypt and view the key
- **Delete:** Permanently remove a key from the extension
- **Backup:** Export all keys as an encrypted `.Signify` file
- **Restore:** Import keys from a `.Signify` backup file (auto-registers on server)

### Extension Security

- Private keys are **never** stored in plaintext
- Every signing operation requires password entry
- Key is decrypted in memory only during the ~1ms signing operation
- 30-second auto-wipe timer on decrypted keys
- All inter-component communication uses persistent port connections
- No `chrome.runtime.sendMessage` calls without try-catch error handling

---

## Integrating Into Any Website

### Method 1: Full SDK Integration (Recommended)

```html
<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl-fast.min.js"></script>
    <script src="https://your-server.com/sdk/signifyauth.js"></script>
</head>
<body>
    <button id="login">Log In with SignifyAuth</button>
    <div id="user-info" style="display:none">
        <p>Welcome, <span id="username"></span>!</p>
        <button id="logout">Log Out</button>
    </div>

    <script>
        var auth = new SignifyAuth({ serverUrl: 'https://auth.yourdomain.com' });
        var currentSession = null;

        document.getElementById('login').addEventListener('click', function () {
            var publicKey = prompt('Paste your public key:');
            if (!publicKey) return;

            auth.login(publicKey).then(function (session) {
                currentSession = session;
                document.getElementById('username').textContent = session.username;
                document.getElementById('user-info').style.display = 'block';
                document.getElementById('login').style.display = 'none';
            }).catch(function (err) {
                alert('Login failed: ' + err.message);
            });
        });

        document.getElementById('logout').addEventListener('click', function () {
            if (currentSession) {
                auth.logout(currentSession.sessionToken).then(function () {
                    currentSession = null;
                    document.getElementById('user-info').style.display = 'none';
                    document.getElementById('login').style.display = 'block';
                });
            }
        });
    </script>
</body>
</html>
```

### Method 2: Extension Communication (Advanced)

For websites that want deep integration with the extension:

```javascript
// Check if extension is available
window.postMessage({
    _signifyRequest: true,
    _requestId: 'check-1',
    type: 'check-keys'
}, window.location.origin);

window.addEventListener('message', function (event) {
    if (event.data._signifyResponse && event.data._requestId === 'check-1') {
        if (event.data.hasKeys) {
            console.log('Extension has', event.data.keyCount, 'keys');
        }
    }
});
```

### Method 3: Account Selection Flow

```javascript
// Ask extension which account to use
window.postMessage({
    _signifyRequest: true,
    _requestId: 'select-1',
    type: 'select-key'
}, window.location.origin);

window.addEventListener('message', function (event) {
    if (event.data._signifyResponse && event.data._requestId === 'select-1') {
        if (event.data.selectedPublicKey) {
            console.log('User selected:', event.data.selectedPublicKey);
            // Now request challenge for this key
        }
    }
});
```

### Method 4: Full Login Flow (Extension + Server)

```javascript
var auth = new SignifyAuth({ serverUrl: 'https://auth.yourdomain.com' });

// Step 1: Check extension
auth.checkExtension().then(function (available) {
    if (!available) {
        alert('Install the SignifyAuth extension');
        return;
    }

    // Step 2: Select account in extension
    auth.selectKeyFromExtension().then(function (publicKey) {

        // Step 3: Login with selected key
        auth.loginWithExtension(publicKey).then(function (session) {
            console.log('Logged in!', session);
        });
    });
});
```

---

## Cryptographic Details

### Algorithms

| Component | Algorithm | Details |
|-----------|-----------|---------|
| **Signing** | Ed25519 | 32-byte public key, 64-byte secret key, 64-byte signature |
| **Key Encryption** | AES-256-GCM | 256-bit key, 12-byte IV, authenticated encryption |
| **Key Derivation** | PBKDF2 | SHA-256, 600,000 iterations, 32-byte salt |
| **Challenge Generation** | `crypto.randomBytes` | 32 bytes (256 bits) of entropy |
| **Nonce Generation** | `crypto.randomBytes` | 16 bytes (128 bits) of entropy |

### Key Formats

| Type | Format | Length |
|------|--------|--------|
| **Public Key** | Base64-encoded | 44 characters (32 bytes) |
| **Secret Key** | Base64-encoded | 88 characters (64 bytes) |
| **Signature** | Base64-encoded | 88 characters (64 bytes) |
| **Encrypted Key** | Base64-encoded (salt + IV + ciphertext) | ~200 characters |

### Challenge Lifecycle

1. **Created:** Random 32-byte value, timestamped
2. **Issued:** Sent to client with session ID
3. **Signed:** Client signs with Ed25519
4. **Verified:** Server verifies signature
5. **Expired:** Auto-deleted after 5 minutes
6. **Single-use:** Cannot be reused after verification

### Backup File Format (`.Signify`)

```json
{
  "type": "signifyauth-backup-encrypted",
  "version": 1,
  "data": "base64-encoded-AES-256-GCM-encrypted-JSON"
}
```

The encrypted data, when decrypted, contains:

```json
{
  "type": "signifyauth-backup",
  "version": 1,
  "keys": [
    {
      "id": "unique-id",
      "name": "My Key",
      "publicKey": "base64-public-key",
      "encryptedSecretKey": "base64-encrypted-secret-key",
      "createdAt": "2024-01-01T00:00:00.000Z"
    }
  ],
  "createdAt": "2024-01-01T00:00:00.000Z"
}
```

---

## Security Hardening

### For Production Deployment

1. **Enable HTTPS** — All communication must be encrypted in transit
2. **Set security headers** — CSP, HSTS, X-Frame-Options (see Nginx config above)
3. **Rate limiting** — Built-in rate limiting (10/min register, 30/min challenge)
4. **Input validation** — Server validates all inputs before processing
5. **Error handling** — Global error handler prevents stack trace leaks
6. **Session expiry** — Sessions expire after 24 hours
7. **Challenge expiry** — Challenges expire after 5 minutes

### For Website Operators

- **Use HTTPS** — Never serve over HTTP in production
- **Store only public keys** — Never request or store private keys
- **Validate inputs** — The server validates key format and signature correctness
- **Implement CSP** — Content Security Policy prevents XSS attacks
- **Monitor rate limits** — Watch for unusual authentication patterns

### For Users

- **Protect your private key** — It's your identity
- **Use a strong password** — It encrypts your key in the extension
- **Back up your key** — Download and store securely (e.g., USB drive)
- **Never share your private key** — Anyone with it can impersonate you
- **If you lose it, it's gone** — There is no recovery mechanism

### Threat Model

| Attacker | Can Do | Cannot Do |
|----------|--------|-----------|
| **Knows your public key** | Nothing useful | Log in as you |
| **Steals server database** | See public keys only | Forge signatures |
| **Intercepts network traffic** | See encrypted signatures | Replay them (challenges are unique) |
| **Has your device** | Nothing (key is password-protected) | Decrypt without password |
| **Knows your password** | Nothing (needs the encrypted key) | Decrypt without the key file |

---

## FAQ

### Why two signatures instead of one?

A single signature proves "I own this key." But it doesn't prove "I'm still here." The two-signature protocol adds session confirmation — the second signature proves the user is actively present and the session is genuine, preventing replay attacks.

### What if I lose my private key?

You cannot recover it. There is no "forgot password" option. This is by design — it's what makes the system truly zero-knowledge. Back up your key using the extension's backup feature.

### Can I use this without the extension?

Yes. The JavaScript SDK (`sdk/signifyauth.js`) handles everything in the browser. The extension provides a better UX (encrypted key storage, password-protected signing) but isn't required.

### Does the server ever see my private key?

Never. The server only stores your public key. All signing happens locally in the extension or SDK.

### Can I log in from multiple devices?

Yes. Import your private key (or backup file) into the extension on each device. Each device must have the extension installed.

### What if the server is compromised?

An attacker would only see public keys. They cannot:
- Log in as any user (requires the private key)
- Decrypt any private keys (encrypted with user passwords)
- Replay old sessions (challenges are single-use and time-limited)

### Is this quantum-resistant?

Ed25519 is not quantum-resistant. For post-quantum security, the signing algorithm could be replaced with a quantum-resistant alternative (e.g., CRYSTALS-Dilithium). The architecture supports algorithm swapping.

### How do I integrate this into my existing website?

Use the JavaScript SDK. Add two script tags, initialize with your server URL, and call `auth.login()` or `auth.loginWithExtension()`. See the [Integrating Into Any Website](#integrating-into-any-website) section for complete examples.

### Can I customize the extension UI?

Yes. Edit `extension/popup/popup.html` and `extension/popup/popup.css` to customize the appearance. The extension uses a dark theme with CSS variables that can be easily modified.

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- — Ed25519 cryptography
- — AES-256-GCM encryption
- — Extension architecture (Chrome Extensions Manifest V3)
