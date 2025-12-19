#!/usr/bin/env python3
import requests
import argparse
import random
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

init(autoreset=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
]

JS_ENDPOINT_REGEX = r"""(?:"|')(/(?:api|v1|v2|auth|admin|user|users|login|logout|register|dashboard|graphql)[^"' ]+)(?:"|')"""

found_js = set()
found_endpoints = set()

def banner():
    print(Fore.CYAN + """
    =====================================
      PyEnumScanner v3.0
      JS Endpoint Extractor
      Author: zzzboom
    =====================================
    """)

def parse_args():
    parser = argparse.ArgumentParser(description="Advanced Web Enumeration Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", default="wordlists/common.txt")
    parser.add_argument("-t", "--threads", type=int, default=15)
    parser.add_argument("-o", "--output", help="Save scan results")
    parser.add_argument("--extract-js", action="store_true", help="Extract JS endpoints")
    return parser.parse_args()

def headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

def load_wordlist(path):
    try:
        with open(path, "r") as f:
            return f.read().splitlines()
    except:
        print(Fore.RED + "[!] Wordlist not found")
        exit(1)

def scan_path(base_url, path, output_file):
    full_url = urljoin(base_url, path)

    try:
        r = requests.get(full_url, headers=headers(), timeout=6, allow_redirects=False)
        code = r.status_code

        if code in [200, 301, 302, 403]:
            msg = f"[+] {full_url} -> {code}"
            print(Fore.GREEN + msg)

            if output_file:
                with open(output_file, "a") as f:
                    f.write(msg + "\n")

            if full_url.endswith(".js") and code == 200:
                found_js.add(full_url)

    except requests.RequestException:
        pass

def extract_js_endpoints(js_url):
    try:
        r = requests.get(js_url, headers=headers(), timeout=6)
        matches = re.findall(JS_ENDPOINT_REGEX, r.text)

        for ep in matches:
            if ep not in found_endpoints:
                found_endpoints.add(ep)
                print(Fore.YELLOW + f"[JS] {ep}")

    except requests.RequestException:
        pass

def start_scan(url, words, threads, output_file, extract_js):
    print(Fore.BLUE + f"[+] Target: {url}")
    print(Fore.BLUE + f"[+] Wordlist size: {len(words)}")
    print(Fore.BLUE + "[+] Scanning...\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for word in words:
            executor.submit(scan_path, url, word, output_file)

    if extract_js and found_js:
        print(Fore.CYAN + "\n[+] Extracting JS endpoints...\n")
        for js in found_js:
            extract_js_endpoints(js)

        if output_file:
            with open(output_file, "a") as f:
                f.write("\n[JS Endpoints]\n")
                for ep in found_endpoints:
                    f.write(ep + "\n")

def main():
    banner()
    args = parse_args()
    words = load_wordlist(args.wordlist)
    start_scan(args.url, words, args.threads, args.output, args.extract_js)

if __name__ == "__main__":
    main()
