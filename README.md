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

## Operating Systems
   Linux/Windows


##  Installation

1. **Clone or download the repository:**
   ```bash
   git clone https://github.com/n4m40xr00t/nanokia
   cd nanokia
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt 
   ```

##  Usage

### Interactive Usage

```bash
python3 nanokia.py <ip>
```

### Command-Line Arguments

```bash
usage: nanokia.py [-h] [-u USERNAME] [-p PASSWORD] [-v] [-o DIR] [--download-only] [--list-devices] [--dump-wifi] [--dump-accounts] [--system-info]
                  [--dump-tr069] [--dump-hashes] [--full-dump] [--enable-ssh] [--ssh-user SSH_USER] [--ssh-pass SSH_PASS]
                  target

naNOKIA - Nokia Router Configuration Tool

positional arguments:
  target                Target router IP address (e.g., 192.168.1.254)

options:
  -h, --help            show this help message and exit
  -u, --username USERNAME
                        Login username (default: AdminGPON)
  -p, --password PASSWORD
                        Login password (default: ALC#FGU)
  -v, --verbose         Enable verbose output
  -o, --output-dir DIR  Output directory for config files (default: naNOKIA_configs)
  --download-only       Download & decrypt config only
  --list-devices        List connected devices
  --dump-wifi           Dump WiFi credentials
  --dump-accounts       Dump user accounts
  --system-info         Show system information
  --dump-tr069          Dump TR-069 configuration
  --dump-hashes         Extract password hashes
  --full-dump           Full information dump (all above)
  --enable-ssh          Enable SSH/Telnet access
  --ssh-user SSH_USER   SSH username for --enable-ssh (default: ONTUSER)
  --ssh-pass SSH_PASS   SSH password for --enable-ssh (default: admin)
                                                                            
```
## ⚠️ Disclaimer

**This tool is intended for educational purposes, security research, and authorized network administration only.**

- Only use this tool on devices you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for any misuse or damage caused by this tool
- Always comply with local laws and regulations


---

**Note:** Always ensure you have proper authorization before testing or analyzing network devices.
