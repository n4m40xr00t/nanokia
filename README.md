# naNOKIA

A powerful Python-based configuration management and security analysis tool for Nokia G-1425G-A routers.

<p align="center">
  <img src="https://github.com/n4m40xr00t/nanokia/blob/main/screenshots/option_menu.png?raw=true" alt="Help menu screeenshot" width="1000px"/>
</p>

## Overview

**naNOKIA** is a comprehensive toolkit designed for security researchers and network administrators to interact with Nokia G-1425G-A routers. The tool automates authentication, configuration backup, decryption, and credential extraction processes.

## Features

- **Automated Authentication** - RSA+AES hybrid encryption for secure login
- **Configuration Download** - Backup router configurations remotely
- **Config Decryption** - Decrypt and decompress Nokia configuration files (AES-128-CBC & AES-256-CBC with PKCS)
- **WiFi Credential Extraction** - Extract all WiFi SSIDs and passwords
- **Device Discovery** - List all connected devices with MAC/IP addresses
- **Account Dumping** - Extract web admin, telnet/SSH, super user, and TR-069 credentials
- **System Information** - Display detailed router system information


<p align="center">
  <img src="https://github.com/n4m40xr00t/nanokia/blob/main/screenshots/help_menu.png?raw=true" alt="Help menu screeenshot" width="1000px"/>
</p>

##  Requirements

- Python 3.6+
- Required Python packages:
  - `requests`
  - `pycryptodome`

##  Installation

1. **Clone or download the repository:**
   ```bash
   git clone <your-repo-url>
   cd router_test
   ```

2. **Install dependencies:**
   ```bash
   pip install requests pycryptodome
   ```

##  Usage

### Basic Usage

```bash
python nanokia.py <router_ip>
```

### Command-Line Arguments

```bash
python nanokia.py <target_ip> [options]

Positional Arguments:
  target                Target router IP address

Optional Arguments:
  -u, --username        Username (default: AdminGPON)
  -p, --password        Password (default: ALC#FGU)
  -o, --output          Output directory (default: naNOKIA_configs)
  -v, --verbose         Enable verbose output
  --download-only       Only download config (skip decrypt/parse)
  --decrypt-only FILE   Decrypt existing config file
  --parse-only FILE     Parse existing XML file
  --help                Show help menu
```

### Example Commands

**Download and decrypt router config:**
```bash
python nanokia.py 192.168.1.1
```

**Use custom credentials:**
```bash
python nanokia.py 192.168.1.1 -u admin -p mypassword
```

**Enable verbose mode:**
```bash
python nanokia.py 192.168.1.1 -v
```

**Only download config:**
```bash
python nanokia.py 192.168.1.1 --download-only
```

**Decrypt existing config file:**
```bash
python nanokia.py 192.168.1.1 --decrypt-only config.cfg
```

**Parse existing XML config:**
```bash
python nanokia.py 192.168.1.1 --parse-only config-23102025-232854.xml
```

## ⚠️ Disclaimer

**This tool is intended for educational purposes, security research, and authorized network administration only.**

- Only use this tool on devices you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for any misuse or damage caused by this tool
- Always comply with local laws and regulations


---

**Note:** Always ensure you have proper authorization before testing or analyzing network devices.
