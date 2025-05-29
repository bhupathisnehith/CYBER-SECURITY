import os
import hashlib
import json
import datetime

HASH_FILE_NAME = ".file_hashes.json"  # Hidden hash file
HASH_ALGO = "sha256"

# Separate block for file uploads
from google.colab import files
uploaded = files.upload()
os.makedirs('monitor_directory', exist_ok=True)
for filename in uploaded.keys():
    os.rename(filename, f'monitor_directory/{filename}')

def hash_file(filepath):
    """Returns the hash of a file using the specified algorithm."""
    h = hashlib.new(HASH_ALGO)
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        return None

def scan_directory(directory):
    """Walks through a directory and computes hash of each file."""
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            if file == HASH_FILE_NAME:  # Skip hash file itself
                continue
            rel_path = os.path.relpath(full_path, directory)
            file_hashes[rel_path] = hash_file(full_path)
    return file_hashes

def save_hashes(hashes, directory):
    """Saves hash dictionary to a JSON file."""
    hash_file_path = os.path.join(directory, HASH_FILE_NAME)
    metadata = {
        "generated_at": datetime.datetime.now().isoformat(),
        "hashes": hashes
    }
    with open(hash_file_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Hashes saved to: {hash_file_path}")

def load_hashes(directory):
    """Loads hash data from the JSON file."""
    hash_file_path = os.path.join(directory, HASH_FILE_NAME)
    if os.path.exists(hash_file_path):
        with open(hash_file_path, 'r') as f:
            return json.load(f).get("hashes", {})
    return {}

def check_integrity(current_hashes, original_hashes):
    """Compares current and original hashes and prints differences."""
    print("\nFile Integrity Report:")
    print("-" * 40)
    changes = 0
    for path, hash_val in current_hashes.items():
        if path not in original_hashes:
            print(f"[NEW]      {path}")
            changes += 1
        elif original_hashes[path] != hash_val:
            print(f"[MODIFIED] {path}")
            changes += 1
    for path in original_hashes:
        if path not in current_hashes:
            print(f"[DELETED]  {path}")
            changes += 1
    if changes == 0:
        print("[OK] No changes detected.")

def main():
    print("=== File Integrity Monitor===\n")
    directory = input("Enter the directory to monitor: ").strip()

    if not os.path.isdir(directory):
        print("[!] Invalid directory. Please check the path.")
        return

    mode = input("Choose mode: [s]ave hashes / [c]check integrity: ").lower()
    current_hashes = scan_directory(directory)

    if mode == 's':
        save_hashes(current_hashes, directory)
    elif mode == 'c':
        original_hashes = load_hashes(directory)
        if not original_hashes:
            print("[!] No previous hash data found. Please run in save mode first.")
            return
        check_integrity(current_hashes, original_hashes)
    else:
        print("[!] Invalid mode. Choose 's' or 'c'.")

if __name__ == "__main__":
    main()
# to excute the code to monitor: monitor_directory
