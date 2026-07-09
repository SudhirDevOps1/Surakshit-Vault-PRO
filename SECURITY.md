# Security Policy / सुरक्षा नीति

## 🛡️ Supported Versions / समर्थित संस्करण

| Version | Supported          |
| ------- | ------------------ |
| 4.1.x   | ✅ Active          |
| 4.0.x   | ⚠️ Critical fixes only |
| < 4.0   | ❌ End of life     |

## 🔐 Reporting a Vulnerability / भेद्यता रिपोर्ट करना

**English:** If you discover a security vulnerability in Surakshit Vault PRO, please report it privately. **Do not open a public GitHub issue** for security vulnerabilities.

**हिन्दी:** यदि आप Surakshit Vault PRO में कोई सुरक्षा भेद्यता खोजते हैं, तो कृपया इसे निजी तौर पर रिपोर्ट करें। सुरक्षा भेद्यताओं के लिए **सार्वजनिक GitHub issue न खोलें**।

### 📧 Contact / संपर्क

- **Email / ईमेल**: security@surakshitlabs.dev
- **PGP Key / PGP कुंजी**: [Request from security@surakshitlabs.dev]
- **Response time / प्रतिक्रिया समय**: Within 48 hours

### 📋 What to Include / क्या शामिल करें

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)
5. Your name/handle for credit (optional)

### 🏆 Hall of Fame / प्रतिष्ठा हॉल

Security researchers who report valid vulnerabilities will be credited here (with permission).

---

## 🔒 Security Architecture / सुरक्षा वास्तुकला

### Cryptographic Primitives
- **PBKDF2-HMAC-SHA-256** with 1,000,000 iterations
- **AES-256-GCM** authenticated encryption
- **CSPRNG** (`crypto.getRandomValues`) for all randomness
- **16-byte salt** + **12-byte IV** per encryption

### Threat Mitigations
- Brute force → PBKDF2 1M iterations
- Rainbow tables → 16-byte random salt
- Replay attacks → 12-byte random IV
- Tampering → AES-GCM authentication tag
- Forensics → Burn-After-Reading + clipboard auto-wipe
- Keyloggers → Anti-keylogger shuffled keypad
- Server breaches → No server (zero attack surface)

### Audit Status
- ✅ Code reviewed for OWASP Top 10
- ✅ No external crypto dependencies (only native Web Crypto)
- ✅ No telemetry, analytics, or tracking
- ✅ No third-party scripts at runtime
- ✅ CSP-compatible (no inline scripts except inline SVG)

## © 2026 Surakshit Labs Pvt. Ltd. — All Rights Reserved
