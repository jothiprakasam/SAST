# Aegis SAST - Static Application Security Testing Engine & Web Dashboard

**Aegis SAST** is a static application security testing (SAST) platform for Python applications, featuring an AST inspection engine, memory footprint heuristics, dependency Software Composition Analysis (SCA), and Google Gemini-powered threat intelligence correlated with the CISA Known Exploited Vulnerabilities (KEV) catalog.

---

## Key Features

1. **Local Project Scanning**
   - Scans full local codebases recursively for security vulnerabilities.
   - Computes an overall Security Health Score (0-100, Grades A to F).
   - Interactive local directory explorer to pick folders with Python files.
   - Software Composition Analysis (SCA) checking `requirements.txt` against vulnerable components.
   - Detects circular dependencies and import graph cycles.
   - Supports scanning extracted `.zip` project uploads.

2. **Single File & Snippet Scanning**
   - **Interactive Code Editor**: Test code snippets directly with line numbering and syntax formatting.
   - **1-Click Vulnerability Presets**: Instant loadable test cases for Command Injection, SQL Injection, Insecure Deserialization (pickle), Hardcoded Secrets, Weak Cryptography (MD5), Insecure Temp Files, and Debug Flags.
   - **Local File Path Scanner**: Target specific `.py` files on disk.
   - **Drag-and-Drop File Upload**: Scan individual Python files directly.
   - **Context Highlighting**: Pinpoints exact offending lines with code context and line-by-line inspection.
   - **Remediation Guides**: Actionable guidance and CWE taxonomy mapping for each finding.

3. **AST & Call-Graph Object Model**
   - Structural AST parsing and hierarchical JSON visualization.
   - Call graph construction with DFS recursion cycle detection.
   - Heuristic memory (RAM) consumption estimation.

4. **AI & CISA KEV Threat Intelligence (RAG)**
   - Correlates static scanner results against live CISA Known Exploited Vulnerabilities catalog.
   - Contextual risk analysis and remediation prioritization via Google Gemini.
   - Graceful operation: static engine runs 100% locally with zero external API requirements.

---

## Quick Start

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Start the Server & Web Dashboard
```powershell
python server.py
```
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

### 3. Run the Automated Test Suite
```powershell
python test_suite.py
```

---

## API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves the web UI dashboard |
| `GET` | `/health` | Health check & engine status |
| `GET` | `/api/stats` | Active rule catalog & engine metadata |
| `POST` | `/api/scan/file` | Scan an individual `.py` file on disk |
| `POST` | `/api/scan/code` | Scan raw Python source code string |
| `POST` | `/api/scan/project` | Scan an entire local project folder |
| `POST` | `/api/scan/upload` | Upload and scan a `.py` file or `.zip` project |
| `GET` | `/api/filesystem/browse` | Browse local directories and discover Python files |
| `POST` | `/api/data_access` | AST tree structure and estimated RAM |
| `POST` | `/api/rag_cve` | Correlated CISA KEV + Gemini threat report |
| `POST` | `/api/config/gemini` | Configure or update Gemini API key |

---

## Supported Security Rules & CWEs

- **Command Injection (`CWE-78`)**: `subprocess(shell=True)`, `os.system`, `os.popen`
- **SQL Injection (`CWE-89`)**: Dynamic string formatting and string concatenation into SQL queries
- **Insecure Deserialization (`CWE-502`)**: `pickle.loads`, `yaml.load` without SafeLoader
- **Hardcoded Secrets (`CWE-798`)**: Embedded API tokens, secret keys, passwords
- **Dangerous Sinks (`CWE-95`)**: `eval()`, `exec()`, `compile()`
- **Weak Cryptography (`CWE-327`)**: `hashlib.md5()`, `hashlib.sha1()`
- **Insecure Temp Files (`CWE-377`)**: `tempfile.mktemp()` race conditions
- **Insecure Debug Flags (`CWE-489`)**: `DEBUG = True` active in configuration
- **XML Vulnerabilities (`CWE-611`)**: Unsafe XML entity parsing
- **Insecure Imports (`CWE-676`)**: Deprecated or high-risk modules (`telnetlib`, `cPickle`, `imp`)
- **Poor Error Handling (`CWE-391`)**: Bare `except:` statements
- **Import Cycles (`CWE-400`)**: Circular import detection in project graph
- **Vulnerable Dependencies (`CWE-1395`)**: SCA version checking with semantic version comparisons
