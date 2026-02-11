# OpenClaw Weak Token Brute-forcer

An auditing script designed to identify instances of **OpenClaw** using default or weak authentication tokens.

## 🛡️ Educational Purpose Only

This tool is developed for **authorized penetration testing** and **security research**. Many automated deployment scripts for OpenClaw use hardcoded or weak "placeholder" tokens. This script helps administrators identify if their instances are exposed. Use of this tool against targets without prior consent is illegal.

---


## 🛠️ Setup & Configuration

### 1. Requirements

* Python 3.8+
* Dependencies: `websockets`, `cryptography`

```bash
pip install websockets cryptography

```

### 2. Input Files

The script automatically looks for two text  files in the root directory:

| File | Format | Description |
| --- | --- | --- |
| **`targets.txt`** | `ws://host:port` or `wss://host:port` |Target Dictionary. One target per line. |
| **`tokens.txt`** | `your_token_here` | Token Dictionary. One token per line to test against targets. |

> **Note:** On the first run, the script will generate template files for you if they are missing.

---

## 🚀 Usage

Simply run the main script. It will load all combinations of targets and tokens and process them with a default concurrency limit of 10.

```bash
python3 brutecraw.py
```
### Understanding the Output

* ✅ **Success:** A valid combination was found and saved to `success_log.txt`.
* ❌ **Failed:** The token was rejected by the gateway.
* ⚠️ **Exception:** Network timeout or connection refusal.

---


