# PyEnumScanner

PyEnumScanner is a Python-based web enumeration and reconnaissance tool designed for penetration testers and security learners.  
It performs directory enumeration and extracts hidden API endpoints from JavaScript files — a common real‑world recon technique.

This project is built step-by-step as a learning and portfolio tool, inspired by tools like Gobuster and modern JS recon workflows.

---

## 🚀 Features

- Directory and file enumeration
- Multi-threaded scanning
- Random User-Agent rotation
- JavaScript file discovery
- Hidden API endpoint extraction from JS
- Colored terminal output
- Optional result saving to file
- Clean CLI interface

---

## 🛠️ Installation

Clone the repository:

```bash
git clone https://github.com/the-artist111/PyEnumScanner.git
cd PyEnumScanner 
```

Install dependencies:

```pip install -r requirements.txt```

⚙️ Usage

Basic directory scan (uses built-in default wordlist):

```python pyenumscanner.py -u https://example.com```


Scan with JavaScript endpoint extraction:

```python pyenumscanner.py -u https://example.com --extract-js```


Save results to a file:

```python pyenumscanner.py -u https://example.com --extract-js -o results.txt```


Increase scan speed (threads):

```python pyenumscanner.py -u https://example.com -t 30```


Use a custom wordlist (absolute or relative path):

```python pyenumscanner.py -u https://example.com -w /path/to/wordlist.txt```

Save results to a file
```python pyenumscanner.py -u https://example.com --extract-js -o results.txt```

Increase scan speed (threads)
```python pyenumscanner.py -u https://example.com -t 30```
