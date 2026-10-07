# SAST

Static Application Security Testing (SAST) is a Python-based security analysis project that scans source code for potentially dangerous patterns and correlates findings with known exploited vulnerabilities. It combines a FastAPI backend, static AST inspection, dependency checks, and a React frontend for interactive analysis.

## Overview

This repository provides a lightweight security scanning workflow for Python projects, with support for:

- Static vulnerability scanning of Python source files
- Detection of dangerous code patterns such as command injection, deserialization issues, hardcoded secrets, weak hashing, and unsafe imports
- Optional AST and memory-access analysis for deeper inspection
- Dependency checks against a curated set of known vulnerable library versions
- Correlation of scan results with current CISA KEV CVEs using Gemini AI
- Web UI for uploading projects, scanning code, and reviewing results
- GitHub repository import and authentication support

## Architecture

### Backend
- Python 3
- FastAPI server (`server.py`)
- Static AST analysis engine (`engine.py`)
- Authentication and OAuth helpers (`auth.py`)
- Database abstraction and storage utilities (`db_manager.py`)
- Data access and AST analysis helpers (`data_access.py`)

### Frontend
- React + Vite + TypeScript
- Tailwind CSS
- Located in the `frontend/` directory

## Repository Structure

```text
SAST/
├── auth.py                  # OAuth / GitHub auth routes and utility helpers
├── data_access.py           # Data-flow / memory-space analysis logic
├── db_manager.py            # Database management and persistence helpers
├── engine.py                # AST-based security scanner and dependency checks
├── frontend/                # React + Vite frontend
│   ├── src/
│   ├── index.html
│   ├── package.json
│   ├── tailwind.config.cjs
│   └── vite.config.ts
├── project_test/            # Sample test project for scanning
├── rag.py                  # Additional RAG / CVE analysis logic
├── requirements.txt         # Python dependencies
├── scripts/                # Helper scripts
├── server.py                # FastAPI application entry point
├── server_imports_temp.py   # Temporary import helper / draft code
├── .gitignore
└── README.md               # Project documentation
```

## Features

### Static Code Analysis
The engine scans Python files using Python's AST and flags patterns such as:

- `eval`, `exec`, `os.system`, `subprocess` with `shell=True`
- `pickle.load`, `yaml.load` without safe loader, insecure XML parsing
- Hardcoded secrets and sensitive variables
- Weak hash usage such as MD5 and SHA1
- Dangerous imports and unsafe libraries
- Bare `except:` blocks and debug assertions
- Potential SQL injection via string concatenation

### Dependency / SCA Checks
The scanner inspects `requirements.txt` and flags known risky dependency versions for examples such as:

- `urllib3`
- `python-json-logger`
- `python-socketio`
- `aiohttp`

### AI-Driven CVE Correlation
The `rag_cve` endpoint uses the CISA KEV vulnerability feed and correlates it with code findings to help prioritize dangerous issues in the project context.

## Prerequisites

- Python 3.10+
- Node.js 18+
- npm
- Git

## Setup

### 1) Clone the repository

```bash
git clone https://github.com/jothiprakasam/SAST.git
cd SAST
```

### 2) Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# or
.venv\Scripts\activate      # Windows
```

### 3) Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4) Install frontend dependencies

```bash
cd frontend
npm install
cd ..
```

## Environment Variables

Create a `.env` file in the project root if you want to enable AI-powered CVE analysis:

```env
GEMINI_API_KEY=your_google_gemini_api_key
SESSION_SECRET=change-me
JWT_SECRET=change-me
```

Notes:
- `GEMINI_API_KEY` is optional; the app will still run without it, but `/rag_cve` may be unavailable.
- `SESSION_SECRET` / `JWT_SECRET` are used for session handling and auth flows.

## Running the Application

### Start the backend

```bash
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at:

- `http://localhost:8000`
- Swagger docs: `http://localhost:8000/docs`

### Start the frontend

```bash
cd frontend
npm run dev
```

Then open the Vite local URL (typically `http://localhost:5173`).

## API Overview

### `POST /analyze`
Runs the static scanner on a directory or uploaded project.

Example request body:

```json
{
  "project_path": "./project_test"
}
```

### `POST /data_access`
Collects memory-space and optional AST analysis data.

```json
{
  "project_path": "./project_test",
  "include_ast": true
}
```

### `POST /rag_cve`
Correlates findings with recent KEV CVEs and summarizes high-risk issues for the scanned project.

```json
{
  "project_path": "./project_test",
  "max_cves": 45,
  "days_recent": 60,
  "days_urgent": 30
}
```

### `GET /health`
Returns the backend status.

### `GET /last-results`
Shows whether the last scan and related analyses completed.

## Example Usage

### Scan a project from the CLI

```bash
python - <<'PY'
import requests
r = requests.post('http://localhost:8000/analyze', json={'project_path': './project_test'})
print(r.json())
PY
```

### Run the scanner directly

```bash
python engine.py
```

## Security Notes

This project is intended for security research, code review assistance, and educational use. It is not a full replacement for mature enterprise SAST platforms and should be used carefully in production and regulated environments.

Important considerations:

- The scanner is heuristic and pattern-based
- Results should be reviewed by a developer or security engineer
- AI-generated CVE correlation should be treated as advisory guidance, not definitive risk classification

## Contributing

Contributions are welcome. Suggested improvements include:

- broader language coverage beyond Python
- more precise taint analysis
- richer rule sets for common frameworks
- improved frontend reporting and visualization
- better integration with GitHub repo scanning and CI pipelines

## License

This repository does not currently include a license file. If you intend to publish or share it publicly in a formal capacity, add an appropriate open-source license before distribution.

## Summary

SAST is a practical security scanning project that demonstrates how to combine static analysis, dependency checks, and AI-assisted CVE correlation in a single application. It is suitable for learning, prototyping, and internal code review workflows.

