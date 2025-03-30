# Dropper Builder

This project generates a modular C-based dropper using a Flask backend.

## 🚀 Implemented Modules

### 💉 Injection Techniques
- Remote Process Injection
- APC Injection
- Early Bird Injection

### 📦 Payload Loading Techniques
- In Memory
- Remote Process In Memory
- File Mapping
- Remote Process File Mapping
- Function Stomping

### 🔐 Encryption & Obfuscation
- AES
- RSA
- RC4

### 🕵️ Stealth Techniques
- HWSyscalls ([GitHub](https://github.com/Dec0ne/HWSyscalls/))

## 🛠️ Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Run the Flask API: `python3 backend/app.py`
3. Go to ([http://localhost:8000/](http://localhost:8000/)).

## 📂 Structure
- **backend/** → Flask API & build scripts
- **dropper_core/** → C source code for the dropper

