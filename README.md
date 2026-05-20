# File Encryption Tool

A Python-based file encryption tool implementing AES-256-GCM authenticated encryption, available as both a command-line interface and a desktop GUI.

## Features
- AES-256-GCM encryption with tamper detection
- CLI for scripted/automated use
- tkinter GUI for end users
- Secure key derivation and nonce management

## Requirements
- Python 3.x
- `cryptography` library

## Setup
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage
**CLI**
```bash
python main.py
```

**GUI**
```bash
python gui.py
```