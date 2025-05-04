# 🔐 Secure Data Encryption System

This Streamlit app allows users to **securely store and retrieve sensitive data** using encryption and hashed passkeys. User registration and login are supported with in-memory session storage.
## Streamlit url
https://secure-data-encryption-knazb2yvpwwwnam9tdqotd.streamlit.app/

## 🚀 Features

- 🔒 **Encrypt** text with a custom passkey
- 🔓 **Decrypt** only with correct passkey
- 👤 **User Login & Registration**
- 🧠 Session-based user memory
- ⏳ Locks out after 3 failed decryption attempts
- 🧪 Built with **Streamlit**, **cryptography**, and **hashlib**

---

## 🛠️ Requirements

- Python 3.8+
- `streamlit`
- `cryptography`

Install dependencies with:

```bash
pip install streamlit cryptography
```
## 📦 File Structure
project_folder/
│
├── app.py           # The main Streamlit application
└── README.md        # This file
## ▶️ Running the App Locally
1. Clone the repository or copy the code into a file named app.py:
```bash
git clone https://github.com/your-username/your-repo.git
cd your-repo
```
2. Install the required libraries:
```bash
pip install -r requirements.txt
```
3. Run the app:
```bash
streamlit run app.py
```
## 🧪 How It Works
.All user data and encrypted text is stored in session state only (not persisted on disk).

.Passkeys are hashed using SHA-256 before storage.

.Data is encrypted/decrypted using Fernet from the cryptography package.

.After 3 wrong decryption attempts, the app forces logout for security.

## 🛡️ Security Notes
.Data and credentials are not saved beyond the session.

.This is a proof-of-concept app, suitable for learning and demonstration purposes.

.For production use, consider adding:

    .Persistent storage (database)

    .Password validation & strength enforcement

    .Email-based authentication or OTP


