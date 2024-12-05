# Brainwave_Matrix_Internt2
M=FIGHTER - Malware Scanner Tool  M=FIGHTER is a Python-based tool designed to scan files for potential malware using YARA rules and the VirusTotal API. The tool allows users to perform static analysis on sample files, detecting potential threats based on predefined YARA signatures and VirusTotal's malware database.
Features:

    YARA Rule Scanning: Scans files against a collection of YARA rules to identify known malware patterns.
    VirusTotal Integration: Uses the VirusTotal API to scan files and check for known malware using a vast database of threat intelligence.
    Parallel Scanning: Supports scanning multiple files concurrently, improving efficiency.
    Graphical Feedback: Displays a graphical progress bar during YARA rule loading and scanning.
    Summary Reports: Saves scan results in a CSV file for easy review.

Requirements:

    Python 3.x
    YARA library
    Requests library
    VirusTotal API Key (set up in the .env file)

Setup:

    Clone this repository to your local machine.
    Install the necessary dependencies using pip install -r requirements.txt.
    Add your VirusTotal API key to a .env file (refer to the example in .env.example).
    Place your YARA rules in the yara_rules/ directory and sample files in the samples/ directory.
    Run the tool with python M=FIGHTER.py.

Usage:

    Enter a file path to scan a specific file or leave it empty to scan the entire samples directory.
    View scan results in the scan_summary.csv file.

