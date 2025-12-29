# 🛡️ PwnGuard Pro
**PwnGuard Pro** is a powerful Python CLI tool designed to enhance your digital security by checking if your passwords have been compromised in known data breaches.

## 🚀 Key Features
- **Privacy-Centric:** Uses k-Anonymity (SHA-1 hashing) to ensure your plain-text password is never sent over the internet.
- **Smart Suggestion Engine:** If a password is found to be breached, the tool suggests a cryptographically secure alternative.
- **High Performance:** Optimized with Multi-threading to scan large lists in seconds.

## 🛠️ Installation
```bash
git clone [https://github.com/Emad-AlKhorasani/PwnGuard-Pro.git](https://github.com/Emad-AlKhorasani/PwnGuard-Pro.git)
cd PwnGuard-Pro
pip install -r requirements.txt

Usage:

To scan a list of passwords, use the following command

''' python pwnguard.py -f list.txt -t 20 '''
