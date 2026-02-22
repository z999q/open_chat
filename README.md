# 🔒 Secure E2EE Web Chat

End-to-End Encrypted (E2EE) live chat application built with Python (Flask) and Vanilla JavaScript. It features a WhatsApp-inspired user interface, seamless camera integration, and state-of-the-art cryptographic protocols running entirely in the browser.



## ✨ Key Features
* **Zero-Knowledge Architecture:** The server acts strictly as a blind relay. It cannot read, decrypt, or access any messages or images.
* **Military-Grade Cryptography:** * **Network:** Ephemeral ECDH (P-256) key exchange for Forward Secrecy. Messages are encrypted in transit using AES-256-GCM (Authenticated Encryption).
  * **At-Rest:** Local chat history is stored securely in IndexedDB, encrypted via AES-256-GCM using a key derived from the room password via PBKDF2 (100,000 iterations).
* **Man-in-the-Middle (MITM) Protection:** Automatically generates a "Safety Number" fingerprint from peer public keys to verify connection integrity.
* **Ephemeral Messages:** Chat history is automatically purged from the local database after 24 hours.
* **Replay Protection:** Every message is tagged with a UUID and timestamp to prevent malicious packet replays.
* **XSS-Safe:** Strict Content Security Policy (CSP) and DOM-safe rendering prevent Cross-Site Scripting attacks.
* **WhatsApp-Style UI:** Clean, responsive design optimized for both mobile and desktop.

## 🛠️ Tech Stack
* **Backend:** Python 3, Flask, Flask-SocketIO, Gevent
* **Frontend:** HTML5, CSS3, Vanilla JavaScript
* **Cryptography:** Native Web Crypto API
* **Storage:** Browser IndexedDB
