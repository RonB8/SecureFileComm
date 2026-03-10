# SecureFileComm 🛡️

![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Python 3.12](https://img.shields.io/badge/Python-3.12-yellow.svg)

**SecureFileComm** is a robust Client-Server system enabling secure file storage and encrypted communication. Developed as part of the *Defensive Systems Programming* course, it features a C++ client and a Python server. 

The system ensures confidentiality and integrity by exchanging encryption keys using asymmetric cryptography (RSA) and transferring files via symmetric cryptography (AES), followed by strict checksum validations (CRC).

## ✨ Features

* **Client-Server Architecture:** Clients autonomously initiate communication, exchange encryption keys, and securely upload files to the server.
* **End-to-End Encryption:** * Asymmetric Encryption (RSA 1024-bit) for secure key exchange.
  * Symmetric Encryption (AES-CBC 256-bit) for fast and secure file transfer.
* **Data Integrity:** The server verifies file integrity using Checksum (CRC) validations. Re-transmission is automatically handled upon failure (up to 3 retries).
* **Multi-Client Support:** The server handles multiple clients concurrently using Python's `threading` module.
* **Persistent Database:** Utilizes an SQLite database (`defensive.db`) to store user information, encryption keys, and file metadata, allowing seamless recovery and reconnection.

## 🛠️ System Requirements

### Server
* **Language:** Python 3.12
* **Libraries:** `pycryptodome`
* **Operating System:** Cross-platform (Linux / Windows / macOS)

### Client
* **Language:** C++17
* **Environment:** Visual Studio 2022 (Windows recommended for testing)
* **Libraries:** `Crypto++` (CryptoPP), `winsock2`

## 🚀 Installation & Usage

### 1. Server Setup
Ensure Python 3.12 is installed, then install the required cryptographic library:
```bash
pip install pycryptodome
