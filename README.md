# Dropper Builder

A modular PE dropper builder based on a Flask web app to craft custom droppers that aim at bypassing modern EDR protections.

## ⚠️ Disclaimer

This tool is intended solely for authorized security testing, research, and educational purposes. Misuse of Droppy to deploy unapproved or malicious software is strictly prohibited. The authors and contributors of this project do not assume any liability for damages or legal consequences arising from improper use. By using Droppy, you agree to comply with all applicable laws and regulations in your jurisdiction.

## 🚀 Implemented Modules

### 💉 Injection Techniques
- Remote Process Injection
- APC Injection
- Early Bird Injection

### 📦 Payload Loading Techniques
- In Memory
- File Mapping
- Function Stomping

### 🔐 Encryption & Obfuscation
- AES
- RSA
- RC4
- IPV4/6 hex format
- UUID hex format
- MAC hex format

### 🕵️ Stealth Techniques
- HWSyscalls ([GitHub](https://github.com/Dec0ne/HWSyscalls/))

## 📋 To-Do

- New UI: Build a new React-based user interface.

- ETW Bypass: Implement Event Tracing for Windows (ETW) evasion techniques.

- Unhooking: Implement unhooking support for [multiple DLLs](https://github.com/NUL0x4C/KnownDllUnhook).

- New Output Format: Add support for generating droppers in DLL format.

- Additional Syscall Techniques: Implement syscall mechanisms using [SysWhispers 2](https://github.com/jthuraisamy/SysWhispers2) & [3](https://github.com/klezVirus/SysWhispers3) and [Hell’s Gate](https://github.com/am0nsec/HellsGate) & [Hall](https://github.com/Maldev-Academy/HellHall) techniques.

- New Injection Techniques: [Ghost Writing](https://github.com/itaymigdal/awesome-injection?tab=readme-ov-file#ghost-writing), [Process Herpaderping](https://github.com/jxy-s/herpaderping), [Kernel Callback Tables Injection](https://github.com/0xHossam/KernelCallbackTable-Injection-PoC), [Early Cascade Injection](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/)

## 🛠️ Setup
Use the provided scripts to install the required components, `setup.ps1` or `setup.sh`. These scripts require python3 to be already installed. Once the setup completed simply run the flask web app.

- On Windows 
```powershell
> venv\Script\active
> python app.py
```

- On Linux
```shell
$ venv/bin/activate
$ python3 app.py
``` 

## 📂 Structure
- **backend/** → Flask API & build scripts
- **dropper_core/** → C source code for the dropper

