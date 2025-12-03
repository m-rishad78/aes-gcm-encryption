# 🔐 AES File Encryption & Decryption (Python)

A simple & secure file encryption/decrytion tool built using **AES-256 (GCM Mode)** & **PBKDF2** key derivation.

This script allows you to protect any file using a strong password-based encryption system.

## 🚀 Features

 - **AES-256 encryption (GCM Mode)**
 - **PBKDF2 key derivation** with 100k iterations
 - **Random salt & nonce** for every encryption
 - **Authentication tag** for tamper detection
 - **Password hidden** using getpass()
 - Protects against:
     - Wrong password
     - Modified or corrupted encrypted file
 - Simple interactive **CLI** interface

## 📂 Project Structure

```perl
📁 AES-GCM-File-Encryption
 ├── aes_cipher.py
 └── README.md
 ```

## 📦 Requirements

 Install dependencies via pip:

 ```bash
 pip install pycryptodome
 ```

## 🧠 How it works

 - **16-byte Salt** is generated
 - PBKDF2 derives a **32-byte AES-256 key**.
 - A **12-byte Nonce** is created for AES-GCM
 - AES-GCM Encrypts the file and produces a **16-byte Auth Tag**
 - Output file format:

 ```css
 [Salt][Nonce][Tag][Encrypted_Data]
 ```

 This format contains everything needed for secure decryption.

## 1️⃣ Clone the repository

 ```bash
 git clone https://github.com/m-rishad78/AES-GCM-File-Encryption.git
 ```

## 2️⃣ Navigate to the Project Directory

 ```bash
 cd AES-GCM-File-Encryption
 ```

## ▶️ Usage

 Run the program:

 ```bash
 python aes_cipher.py
 ```

 Then choose an option:

 ```css
    1. Encryption
    2. Decryption
 ```

## 🔑 Encryption Example

 ```css
 Enter the Filename: secret.txt
 Enter the Password: ******
 
 File Has been Successfully Encrypted.
 ```

 This generates:
    secret.txt.enc

## 🔓 Decryption Example

 ```css
 Enter the Filename: secret.txt.enc
 Enter the Password: ******

 File Has been Successfully Decrypted.
 ```

 Restores the original file:
    secret.txt

## ⚠️ Security Notes

 - Use **strong passwords** for better protection
 - Never share the **encrypted file & password together**
 - Thia project is for **learning & personal use**, not enterprise-level security
 - AES-GCM ensures both **confidentiality & integrity**, but password strength still mstters

## ⭐ Contribute

 Feel free to open issues or submit pull requests to improve the project!