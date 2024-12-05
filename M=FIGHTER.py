import os
import yara
import hashlib
import requests
import json
import datetime
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
import pyfiglet
import csv
from tqdm import tqdm  # Import tqdm for progress bar

# ASCII Banner
ascii_banner = pyfiglet.figlet_format("M=FIGHTER", font="slant")
print(ascii_banner)
print("Malware Scanner Tool - A tool to scan files for potential malware using YARA rules and VirusTotal.")
print("-" * 50)
print("Made by ALBATRONIX")
print("-" * 50)

# Load environment variables
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Paths
YARA_RULES_DIR = "/root/malware_scanner/yara_rules/signature-base/yara/"
SAMPLES_DIR = "samples/"
LOGS_DIR = "logs/"
OUTPUT_REPORT = "scan_summary.csv"

# Create necessary directories
os.makedirs(LOGS_DIR, exist_ok=True)

if not os.path.exists(SAMPLES_DIR):
    print(f"Error: Samples directory '{SAMPLES_DIR}' does not exist.")
    exit()

if not os.path.exists(YARA_RULES_DIR):
    print(f"Error: YARA rules directory '{YARA_RULES_DIR}' does not exist.")
    exit()

if not VIRUSTOTAL_API_KEY:
    print("Error: VirusTotal API key not found in environment variables.")
    exit()

# Logging utility
def log_result(filename, result):
    log_file = os.path.join(LOGS_DIR, f"log_{datetime.date.today()}.txt")
    with open(log_file, "a") as f:
        f.write(f"{datetime.datetime.now()}: {filename} - {result}\n")

# Reuse the initialize_yara_rules() function from your original code with graphical representation
def initialize_yara_rules():
    yara_rules = []
    rule_files = []
    
    # Collect rule file paths
    for root, dirs, files in os.walk(YARA_RULES_DIR):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                rule_files.append(os.path.join(root, file))
    
    print(f"Found {len(rule_files)} YARA rule files. Loading...")
    
    # Progress bar for loading YARA rules
    for yara_file_path in tqdm(rule_files, desc="Loading YARA Rules", unit="file"):
        try:
            compiled_rule = yara.compile(filepath=yara_file_path)
            yara_rules.append(compiled_rule)
        except yara.SyntaxError as e:
            # Log syntax errors but don't interrupt the process
            log_result("YARA_RULES", f"Syntax error in {yara_file_path}: {e}")
        except Exception as e:
            # Log general errors
            log_result("YARA_RULES", f"Error compiling {yara_file_path}: {e}")
    
    print("Finished loading YARA rules.")
    return yara_rules

# File Scanning Functions
def scan_with_yara(file_path, yara_rules):
    for rule in yara_rules:
        matches = rule.match(file_path)
        if matches:
            return True, [match.rule for match in matches]
    return False, []

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_with_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        malicious_votes = result["data"]["attributes"]["last_analysis_stats"]["malicious"]
        return malicious_votes > 0, malicious_votes
    elif response.status_code == 404:
        return False, 0  # Hash not found in VirusTotal
    else:
        print(f"Error contacting VirusTotal: {response.status_code}")
        return False, 0

def process_file(file_name, yara_rules, results):
    file_path = os.path.join(SAMPLES_DIR, file_name)
    file_size = os.path.getsize(file_path)
    start_time = datetime.datetime.now()

    # YARA Scan
    yara_detected, rules = scan_with_yara(file_path, yara_rules)
    if yara_detected:
        result = f"YARA detected: {rules}"
        log_result(file_name, result)
        results.append([file_name, "YARA", rules, file_size])
        print(f"{file_name}: YARA detected {rules}")
        return

    # VirusTotal Scan
    file_hash = get_file_hash(file_path)
    vt_detected, malicious_votes = scan_with_virustotal(file_hash)
    if vt_detected:
        result = f"VirusTotal detected ({malicious_votes} malicious votes)"
        log_result(file_name, result)
        results.append([file_name, "VirusTotal", f"{malicious_votes} malicious votes", file_size])
        print(f"{file_name}: VirusTotal detected malware ({malicious_votes} votes)")
    else:
        result = "No malware detected"
        log_result(file_name, result)
        results.append([file_name, "None", "No malware detected", file_size])
        print(f"{file_name}: No malware detected")

    duration = (datetime.datetime.now() - start_time).total_seconds()
    log_result(file_name, f"Scan completed in {duration:.2f} seconds.")

def save_summary_to_csv(results):
    with open(OUTPUT_REPORT, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Filename", "Detection Method", "Details", "File Size (Bytes)"])
        writer.writerows(results)
    print(f"Summary saved to {OUTPUT_REPORT}")

def main():
    print("Loading YARA rules...")
    yara_rules = initialize_yara_rules()
    print(f"Loaded {len(yara_rules)} valid YARA rules.")
    
    user_input = input("Enter file path for scanning or press Enter to scan the entire 'samples' directory: ").strip()

    if user_input:
        global SAMPLES_DIR
        SAMPLES_DIR = user_input
        if not os.path.exists(SAMPLES_DIR):
            print(f"Error: Specified path '{SAMPLES_DIR}' does not exist.")
            return
    
    print("\nScanning files...")
    results = []
    with ThreadPoolExecutor() as executor:
        executor.map(lambda file_name: process_file(file_name, yara_rules, results), os.listdir(SAMPLES_DIR))
    
    save_summary_to_csv(results)

if __name__ == "__main__":
    main()

