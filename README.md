# Linux-Permission-Audit-Python-Script-
This python script will crawl a linux file directory and identify files with misconfigured permissions that present potential vulnerabilities against privilege escalation and violations of confidentiality and integrity of those files. Ensure you always receive authorized permission before you run this script
# Linux-Permission-Audit-Python-Script-

This repository contains a **defensive Linux permission audit tool** written in Python.  
It scans a filesystem for files and directories with potentially risky permission settings, 
such as world-writable files or SUID/SGID executables, and generates a report for review.

⚠️ **Important:** This tool is designed for *authorized system auditing only*.  
Do **not** run it on systems you do not own or manage. It performs read-only checks 
and does **not** modify or exploit anything.

---

## 🔧 Usage

1. **Clone the repository**
   ```bash
   git clone https://github.com/<your-username>/Linux-Permission-Audit-Python-Script-.git
   cd Linux-Permission-Audit-Python-Script-
   
Run the Python script

python3 linux_permission_audit.py --path /home/youruser --output report.csv


Review the output
The script generates a CSV file listing all files and directories with suspicious permissions.

🗂 Example command
python3 linux_permission_audit.py --path /etc --output etc_report.csv --max-paths 5000

🧠 Notes

The script only inspects metadata (read-only).

Useful for compliance audits, security hardening, or educational exercises.

The package.json file is included for compatibility with the code generation platform; it is not required to run the Python script.
