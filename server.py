import os
import shutil
import tempfile
import zipfile
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from collections import Counter
import pathlib

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
import uvicorn
import requests
from dotenv import load_dotenv

# Internal engine and utility modules
from engine import (
    scan_directory,
    scan_file,
    scan_code,
    calculate_security_score,
    summarize_findings_counts,
    CWE_METADATA
)
from data_access import (
    memory_space_data,
    ast_view,
    single_file_data,
    analyze_source_ast_and_memory
)
from rag import run_cve_analysis, fetch_kev_data

load_dotenv()

# Gemini setup - safe initialization without crashing if key is not yet set
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

app = FastAPI(
    title="Aegis SAST - Python Security Scanner",
    description="Advanced Static Application Security Testing (SAST), AST Call-Graph Inspector, and CVE Intelligence Engine",
    version="2.0.0"
)

# Enable CORS for local web UI & API clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory cached states
_last_results: Dict[str, Any] = {
    "analyze": None,
    "file_scan": None,
    "code_scan": None,
    "data_access": None,
    "rag_cve": None,
}

# ─── Pydantic Request Models ─────────────────────────────────────────────────

class ProjectScanRequest(BaseModel):
    project_path: str = "./project_test"

class FileScanRequest(BaseModel):
    file_path: str

class CodeScanRequest(BaseModel):
    code: str
    filename: Optional[str] = "snippet.py"

class DataAccessRequest(BaseModel):
    project_path: str = "./project_test"
    include_ast: bool = False

class FileDataAccessRequest(BaseModel):
    file_path: str
    include_ast: bool = True

class RAGRequest(BaseModel):
    project_path: str = "./project_test"
    api_key: Optional[str] = None
    model: Optional[str] = "gemini-2.5-flash"
    max_cves: int = 45
    days_recent: int = 60
    days_urgent: int = 30

class ApiKeyConfigRequest(BaseModel):
    api_key: str

# ─── System / Health Endpoints ───────────────────────────────────────────────

@app.get("/health")
@app.get("/api/health")
async def health():
    return {
        "status": "online",
        "timestamp": datetime.now().isoformat(),
        "gemini_configured": bool(GEMINI_API_KEY),
        "engine_version": "2.0.0",
        "rules_count": len(CWE_METADATA)
    }

@app.get("/api/stats")
async def get_stats():
    return {
        "total_rules": len(CWE_METADATA),
        "rules": [
            {"category": k, "cwe": v["cwe"], "name": v["name"], "remediation": v["remediation"]}
            for k, v in CWE_METADATA.items()
        ],
        "gemini_active": bool(GEMINI_API_KEY),
        "default_model": GEMINI_MODEL,
        "server_time": datetime.now().isoformat()
    }

@app.get("/api/last-results")
@app.get("/last-results")
async def get_last_results():
    return {
        "last_analyze": _last_results["analyze"] is not None,
        "last_file_scan": _last_results["file_scan"] is not None,
        "last_code_scan": _last_results["code_scan"] is not None,
        "last_data_access": _last_results["data_access"] is not None,
        "last_rag_cve": _last_results["rag_cve"] is not None,
    }

@app.post("/api/config/gemini")
async def configure_gemini(req: ApiKeyConfigRequest):
    global GEMINI_API_KEY
    key = req.api_key.strip()
    if not key:
        raise HTTPException(400, "API key cannot be empty")
    GEMINI_API_KEY = key
    os.environ["GEMINI_API_KEY"] = key
    return {"status": "success", "message": "Gemini API key updated successfully"}

# ─── Filesystem Explorer Endpoints ───────────────────────────────────────────

@app.get("/api/filesystem/browse")
async def browse_filesystem(path: str = Query(default=".")):
    """List subdirectories and python files to simplify path picking in UI."""
    try:
        target = os.path.abspath(path.strip())
        if not os.path.exists(target):
            target = os.getcwd()

        if os.path.isfile(target):
            target = os.path.dirname(target)

        entries = os.listdir(target)
        dirs = []
        py_files = []

        for name in entries:
            # Skip hidden folders like .git
            if name.startswith(".") and name not in [".", ".."]:
                continue
            full_item = os.path.join(target, name)
            try:
                if os.path.isdir(full_item):
                    # Check if contains any .py files inside
                    has_py = False
                    for _, _, file_names in os.walk(full_item):
                        if any(fn.endswith(".py") for fn in file_names):
                            has_py = True
                            break
                    dirs.append({
                        "name": name,
                        "path": full_item,
                        "has_python_files": has_py
                    })
                elif name.endswith(".py"):
                    py_files.append({
                        "name": name,
                        "path": full_item,
                        "size_bytes": os.path.getsize(full_item)
                    })
            except (PermissionError, OSError):
                continue

        parent_dir = os.path.dirname(target) if target != os.path.dirname(target) else None

        return {
            "current_path": target,
            "parent_path": parent_dir,
            "directories": sorted(dirs, key=lambda x: x["name"].lower()),
            "python_files": sorted(py_files, key=lambda x: x["name"].lower()),
            "favorites": [
                {"label": "Project Test", "path": os.path.abspath("./project_test")},
                {"label": "Current Directory", "path": os.path.abspath(".")},
            ]
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to explore filesystem: {str(e)}")

# ─── 1. Single File Scanning ─────────────────────────────────────────────────

@app.post("/api/scan/file")
async def scan_single_file(req: FileScanRequest):
    """Scan an individual Python file on disk."""
    path = req.file_path.strip()
    if not os.path.isfile(path):
        raise HTTPException(400, f"File does not exist or is not a file: {path}")
    if not path.endswith(".py"):
        raise HTTPException(400, "Only Python (.py) files are supported for single file scanning.")

    result = scan_file(path)
    if "error" in result:
        raise HTTPException(400, result["error"])

    payload = {
        "timestamp": datetime.now().isoformat(),
        "scan_type": "file",
        "file_path": path,
        "filename": os.path.basename(path),
        "total_findings": result.get("total_findings", 0),
        "stats": result.get("stats", {}),
        "score": result.get("score", 100),
        "file_size_bytes": result.get("file_size_bytes", 0),
        "line_count": result.get("line_count", 0),
        "findings": result.get("findings", [])
    }
    _last_results["file_scan"] = payload
    return payload

@app.post("/api/scan/code")
async def scan_code_snippet(req: CodeScanRequest):
    """Scan raw Python code passed in request body directly from code editor."""
    code = req.code
    if not code or not code.strip():
        raise HTTPException(400, "Code snippet cannot be empty.")

    filename = req.filename or "snippet.py"
    result = scan_code(code, filename=filename)

    payload = {
        "timestamp": datetime.now().isoformat(),
        "scan_type": "code_snippet",
        "filename": filename,
        "line_count": len(code.splitlines()),
        "total_findings": result.get("total_findings", 0),
        "stats": result.get("stats", {}),
        "score": result.get("score", 100),
        "findings": result.get("findings", []),
        "imported_modules": result.get("imported_modules", [])
    }
    _last_results["code_scan"] = payload
    return payload

@app.post("/api/scan/upload")
async def upload_and_scan(file: UploadFile = File(...)):
    """Upload a single .py file or a .zip archive of a project to scan."""
    filename = file.filename or "uploaded_file"
    ext = os.path.splitext(filename)[1].lower()

    if ext not in [".py", ".zip"]:
        raise HTTPException(400, "Unsupported file format. Please upload a .py file or a .zip archive.")

    temp_dir = tempfile.mkdtemp(prefix="sast_upload_")
    try:
        temp_file_path = os.path.join(temp_dir, filename)
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        if ext == ".py":
            result = scan_file(temp_file_path)
            # Replace temp path with original filename in findings
            for f in result.get("findings", []):
                f["file"] = filename
            payload = {
                "timestamp": datetime.now().isoformat(),
                "scan_type": "uploaded_file",
                "filename": filename,
                "total_findings": result.get("total_findings", 0),
                "stats": result.get("stats", {}),
                "score": result.get("score", 100),
                "findings": result.get("findings", [])
            }
            return payload

        elif ext == ".zip":
            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(temp_file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

            findings = scan_directory(extract_dir)
            # Make paths relative to zip root
            for f in findings:
                rel = os.path.relpath(f["file"], extract_dir)
                f["file"] = rel

            stats = summarize_findings_counts(findings)
            score = calculate_security_score(findings)

            payload = {
                "timestamp": datetime.now().isoformat(),
                "scan_type": "uploaded_zip",
                "filename": filename,
                "total_findings": len(findings),
                "stats": stats,
                "score": score,
                "findings": findings
            }
            return payload

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ─── 2. Local Project Scanning ───────────────────────────────────────────────

@app.post("/api/scan/project")
@app.post("/analyze")
async def scan_project_directory(req: ProjectScanRequest):
    """Scan an entire local project directory."""
    path = req.project_path.strip()
    if not os.path.isdir(path):
        raise HTTPException(400, f"Not a valid directory: {path}")

    findings = scan_directory(path)
    stats = summarize_findings_counts(findings)
    score = calculate_security_score(findings)

    # Group findings by file
    by_file = {}
    for f in findings:
        fname = f.get("file", "unknown")
        if fname not in by_file:
            by_file[fname] = []
        by_file[fname].append(f)

    # Categories breakdown
    cat_counts = Counter(f.get("category", "Unknown") for f in findings)

    result = {
        "timestamp": datetime.now().isoformat(),
        "scan_type": "project",
        "project_path": os.path.abspath(path),
        "total_findings": len(findings),
        "stats": stats,
        "score": score,
        "categories_breakdown": dict(cat_counts),
        "files_with_issues_count": len(by_file),
        "findings": findings
    }

    _last_results["analyze"] = result
    return result

# ─── 3. Data Access (AST + Memory Graph) ─────────────────────────────────────

@app.post("/api/data_access/file")
async def file_data_access(req: FileDataAccessRequest):
    path = req.file_path.strip()
    if not os.path.isfile(path):
        raise HTTPException(400, f"File not found: {path}")
    data = single_file_data(path, include_ast=req.include_ast)
    return {
        "timestamp": datetime.now().isoformat(),
        "file_path": path,
        "data": data
    }

@app.post("/api/data_access")
@app.post("/data_access")
async def project_data_access(req: DataAccessRequest):
    path = req.project_path.strip()
    if not os.path.isdir(path):
        raise HTTPException(400, f"Not a directory: {path}")

    mem_data = memory_space_data(path)
    ast_data = ast_view(path) if req.include_ast else {"note": "AST view skipped (enable include_ast=true)"}

    result = {
        "timestamp": datetime.now().isoformat(),
        "path": os.path.abspath(path),
        "memory_space_data": mem_data,
        "ast_view": ast_data
    }

    _last_results["data_access"] = result
    return result

# ─── 4. CVE + Gemini Correlated Intelligence (RAG) ───────────────────────────

@app.post("/api/rag_cve")
@app.post("/rag_cve")
async def rag_cve_analysis(req: RAGRequest):
    project_path = req.project_path.strip()
    if not os.path.isdir(project_path):
        raise HTTPException(400, f"Not a directory: {project_path}")

    api_key = req.api_key or GEMINI_API_KEY
    if not api_key:
        raise HTTPException(
            400,
            "GEMINI_API_KEY is not configured. Please supply an API key in the request or set it in your .env file."
        )

    model = req.model or GEMINI_MODEL
    res = run_cve_analysis(
        project_path=project_path,
        api_key=api_key,
        model=model,
        max_cves=req.max_cves,
        days_recent=req.days_recent,
        days_urgent=req.days_urgent
    )

    if not res.get("success"):
        raise HTTPException(500, res.get("error", "RAG / CVE analysis failed"))

    _last_results["rag_cve"] = res
    return res

# ─── 5. Static Web UI Mounting ───────────────────────────────────────────────

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    async def serve_index():
        index_file = os.path.join(STATIC_DIR, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "Aegis SAST API online. Static index.html not found."}
else:
    @app.get("/")
    async def root():
        return {
            "message": "Aegis SAST Security & CVE Analysis API is running",
            "version": "2.0.0",
            "endpoints": [
                "POST /api/scan/file      → Scan single file",
                "POST /api/scan/code      → Scan code snippet",
                "POST /api/scan/project   → Scan local project directory",
                "POST /api/scan/upload    → Upload and scan .py or .zip",
                "POST /api/data_access    → AST & memory graph analysis",
                "POST /api/rag_cve        → AI + CISA KEV correlated intelligence",
                "GET  /api/filesystem/browse → Browse local filesystem"
            ]
        }

if __name__ == "__main__":
    print("Starting Aegis SAST Server at http://127.0.0.1:8000 ...")
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)