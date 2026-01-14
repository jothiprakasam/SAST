import os
import shutil
import zipfile
import uuid
import subprocess
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
import uvicorn
from typing import Dict, Any, List, Optional
from collections import Counter
import requests
import json

# Static files + CORS for frontend development
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

# Your modules
from engine import scan_directory
from data_access import memory_space_data, ast_view

# ─── Gemini setup ──────────────────────────────────────────────────────────
from dotenv import load_dotenv
from google import genai

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
client = None
GEMINI_MODEL = "gemini-2.5-flash"
if GEMINI_API_KEY:
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception as e:
        # don't crash the server if the external API or network is unavailable
        print(f"[Gemini] Warning: failed to initialize Gemini client: {e}")
        client = None
else:
    print("[Gemini] GEMINI_API_KEY not set; /rag_cve will be unavailable")

# --- DB manager and auth
import db_manager
import asyncio

# import auth router (registers OAuth endpoints)
from auth import router as auth_router


# ─── FastAPI app ───────────────────────────────────────────────────────────
app = FastAPI(
    title="Python Security & CVE Analysis API",
    description="Endpoints for code scanning, structure analysis and CVE intelligence",
    version="0.1.0"
)

# Session middleware required by authlib to store OAuth state during the redirect flow
# Use dedicated SESSION_SECRET env var in production; fall back to JWT_SECRET for dev convenience
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", os.getenv("JWT_SECRET", "change-me")),
    session_cookie="sast_session",
    max_age=3600,
    same_site="lax",
    https_only=False,
)

# Allow requests from the Vite dev server during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register auth router and startup initialization after `app` exists
app.include_router(auth_router, prefix="/auth")


@app.on_event("startup")
async def startup_database_and_auth():
    # create DB manager singleton and initialize engines using the module to keep references consistent
    mgr = db_manager.make_manager_from_env()
    if db_manager.db_manager is None:
        raise RuntimeError("DB manager initialization failed")
    await db_manager.db_manager.init_engines()
    await db_manager.db_manager.ensure_tables()

# In-memory last results (replace with Redis in production)
_last_results: Dict[str, Dict[str, Any]] = {
    "analyze": None,
    "data_access": None,
    "rag_cve": None,
}

# ─── Request Models ────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    project_path: str = "./project_test"

class DataAccessRequest(BaseModel):
    project_path: str = "./project_test"
    include_ast: bool = False

class RAGRequest(BaseModel):
    project_path: str = "./project_test"      # ← now configurable
    max_cves: int = 45
    days_recent: int = 60
    days_urgent: int = 30

# ─── Helper: Fetch CISA KEV catalog ────────────────────────────────────────
def fetch_kev() -> dict | None:
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(KEV_URL, timeout=15)
        r.raise_for_status()
        print(f"[KEV] Catalog fetched successfully (Last-Modified: {r.headers.get('Last-Modified', 'unknown')})")
        return r.json()
    except requests.exceptions.RequestException as e:
        print(f"[KEV] Error fetching catalog: {e}")
        return None

# ─── Helper: Summarize scanner findings for prompt ─────────────────────────
def summarize_scanner_findings(findings: List[dict]) -> str:
    if not findings:
        return "No vulnerabilities or suspicious patterns detected by the static code scanner."

    severity_count = Counter(f["severity"] for f in findings)
    category_count = Counter(f["category"] for f in findings)

    lines = []
    lines.append(f"Total issues found: {len(findings)}")
    lines.append("Severity breakdown:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in severity_count:
            lines.append(f"  • {sev}: {severity_count[sev]}")

    lines.append("\nMost common issue categories:")
    for cat, count in category_count.most_common(10):
        lines.append(f"  • {cat}: {count} occurrences")

    critical_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")][:6]
    if critical_high:
        lines.append("\nExamples of HIGH/CRITICAL findings:")
        for f in critical_high:
            short_path = os.path.relpath(f["file"], start=os.getcwd())
            lines.append(f"  • {f['severity']} - {f['category']} in {short_path}:{f['line']}")
            lines.append(f"    {f['message'][:140]}{'...' if len(f['message']) > 140 else ''}")

    return "\n".join(lines)

# ─── Workspace Helper ──────────────────────────────────────────────────────
WORKSPACE_DIR = os.path.join(os.getcwd(), "server_workspaces")
os.makedirs(WORKSPACE_DIR, exist_ok=True)

def get_workspace_path(session_id: str) -> str:
    path = os.path.join(WORKSPACE_DIR, session_id)
    os.makedirs(path, exist_ok=True)
    return path

# ─── Helper: Format KEV entries for prompt ─────────────────────────────────
def format_kev_text(relevant_cves: List[dict], max_items: int = 45) -> str:
    text = "CISA Known Exploited Vulnerabilities (recent/urgent):\n\n"
    for item in relevant_cves[:max_items]:
        text += f"• {item['cve']} | {item['vendor']} {item['product']} — {item['name']}\n"
        text += f"  Added: {item.get('added', 'N/A')} | Due: {item.get('due', 'N/A')} | Ransomware: {item.get('ransomware', 'Unknown')}\n"
        text += f"  Action: {item.get('action', 'Apply updates')}\n"
        if notes := item.get('notes'):
            text += f"  Notes: {notes[:180]}...\n"
        text += "\n"
    return text

# ─── Endpoints ─────────────────────────────────────────────────────────────

# --- Workspace Management Endpoints ---

@app.post("/upload-zip")
async def upload_zip_project(request: Request, file: UploadFile = File(...)):
    """Uploads a zip file to the clustered DB, returns a DB-reference path."""
    print(f"[DEBUG] /upload-zip called. Filename: {file.filename}, Content-Type: {file.content_type}")
    
    # Try to identify user (optional)
    owner_id = "anonymous"
    try:
        from auth import _get_token_from_request
        auth_data = await _get_token_from_request(request)
        if auth_data and auth_data.get("sub"):
             owner_id = auth_data.get("sub")
    except: 
        pass

    try:
        # Read file content into memory
        content = await file.read()
        size = len(content)
        file_id = str(uuid.uuid4())
        
        print(f"[DEBUG] [Upload] Read {size} bytes. Checking for DB storage...")
        
        # Select best shard
        if not db_manager.db_manager:
            raise HTTPException(503, "Database manager not initialized")
            
        target = await db_manager.db_manager.get_engine_for_write(size)
        if not target:
             raise HTTPException(507, "No database shard has sufficient space.")
        
        engine, idx = target
        print(f"[DEBUG] [Upload] Selected DB shard {idx}. Saving file {file_id}...")
        
        metadata = {
            "id": file_id,
            "owner_id": owner_id,
            "storage_db": str(idx),
            "metadata": json.dumps({"filename": file.filename, "content_type": file.content_type}),
            "size": size,
            "content": content
        }
        
        await db_manager.db_manager.insert_file(engine, metadata)
        print(f"[DEBUG] [Upload] File saved to DB. ID: {file_id}")

        # Return a special path that analyze() will recognize
        project_ref = f"db://{file_id}"
        
        return {
            "session_id": file_id, 
            "project_path": project_ref, 
            "message": "Project uploaded to Clustered DB."
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"[DEBUG] [Upload] Unexpected error: {e}")
        raise HTTPException(500, f"Server error during upload: {str(e)}")

@app.post("/create-file")
async def create_single_file(request: Request, filename: str = Form(...), content: str = Form(...)):
    """Creates a single file project, zips it, and stores in DB."""
    
    # Auth check (optional, matching upload-zip)
    owner_id = "anonymous"
    try:
        from auth import _get_token_from_request
        auth_data = await _get_token_from_request(request)
        if auth_data and auth_data.get("sub"):
             owner_id = auth_data.get("sub")
    except: 
        pass

    import io
    import zipfile
    
    # Create a zip in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr(filename, content)
    
    zip_content = zip_buffer.getvalue()
    size = len(zip_content)
    file_id = str(uuid.uuid4())
    
    if not db_manager.db_manager:
        raise HTTPException(503, "Database manager not initialized")
        
    target = await db_manager.db_manager.get_engine_for_write(size)
    if not target:
            raise HTTPException(507, "No database shard has sufficient space.")
    
    engine, idx = target
    
    metadata = {
        "id": file_id,
        "owner_id": owner_id,
        "storage_db": str(idx),
        "metadata": json.dumps({"filename": filename, "content_type": "application/zip", "is_single_file": True}),
        "size": size,
        "content": zip_content
    }
    
    await db_manager.db_manager.insert_file(engine, metadata)
    print(f"[DEBUG] [CreateFile] Saved {filename} as db://{file_id}")

    return {
        "session_id": file_id, 
        "project_path": f"db://{file_id}", 
        "message": "File created and stored in Clustered DB."
    }

@app.post("/github/repos")
async def list_github_repos(request: Request, token: str = Form(None), username: str = Form(None)):
    """Lists GitHub repositories for a user or authenticated user."""
    
    # Try to resolve token from the logged in user if not provided in form
    if not token and not username:
        try:
            from auth import _get_token_from_request
            auth_data = await _get_token_from_request(request)
            user_id = auth_data.get("sub")
            if db_manager.db_manager:
                user = await db_manager.db_manager.find_user_by_id(user_id)
                if user and user.get("github_token"):
                    token = user.get("github_token")
        except HTTPException:
            pass # Not authenticated or no token stored
        except ImportError:
            pass

    # If successful, we have a token
    if token:
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
        url = "https://api.github.com/user/repos?sort=updated&per_page=100"
    elif username:
        headers = {"Accept": "application/vnd.github.v3+json"}
        url = f"https://api.github.com/users/{username}/repos?sort=updated&per_page=100"
    else:
        raise HTTPException(400, "Provide either a Personal Access Token or a Username. Connect GitHub account to skip this step.")

    try:
        r = requests.get(url, headers=headers)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        raise HTTPException(400, f"GitHub API Error: {str(e)}")

@app.post("/github/clone")
async def clone_github_repo(request: Request, repo_url: str = Form(...), token: str = Form(None)):
    """Clones a GitHub repository."""
    session_id = str(uuid.uuid4())
    ws_path = get_workspace_path(session_id)
    
    # If token not explicitly provided, try to fetch from stored user session
    if not token:
         try:
            from auth import _get_token_from_request
            auth_data = await _get_token_from_request(request)
            user_id = auth_data.get("sub")
            if db_manager.db_manager:
                user = await db_manager.db_manager.find_user_by_id(user_id)
                if user and user.get("github_token"):
                    token = user.get("github_token")
         except:
             pass

    # Inject token into URL if provided for private repos
    final_url = repo_url
    if token and "github.com" in repo_url:
        protocol, _, domain_path = repo_url.partition("://")
        final_url = f"{protocol}://{token}@{domain_path}"

    try:
        # Use subprocess to call git
        # Note: In production, treat this carefully to avoid command injection if url is not sanitized
        subprocess.check_call(["git", "clone", "--depth", "1", final_url, ws_path], stderr=subprocess.STDOUT)
        
        # Check if it was cloned into a subdir or directly (usually git clone <url> <dir> clones contents into dir)
        # Actually git clone <url> <dir> puts the .git inside <dir>.
        
        return {"session_id": session_id, "project_path": ws_path, "message": "Repository cloned."}
    except subprocess.CalledProcessError as e:
        # Cleanup
        if os.path.exists(ws_path):
            shutil.rmtree(ws_path, ignore_errors=True)
        raise HTTPException(400, f"Git clone failed.")

@app.get("/")
async def root():
    return {
        "message": "Security & CVE Analysis API is running",
        "endpoints": [
            "POST /analyze       → Run vulnerability scanner",
            "POST /data_access   → Get AST + memory/call graph data",
            "POST /rag_cve       → CVE analysis with project context correlation",
            "GET  /health        → Server status",
            "GET  /last-results  → Check last run status"
        ]
    }

@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.now().isoformat()}

@app.get("/last-results")
async def get_last_results():
    return {
        "last_analyze": _last_results["analyze"] is not None,
        "last_data_access": _last_results["data_access"] is not None,
        "last_rag_cve": _last_results["rag_cve"] is not None,
    }

# ─── 1. Vulnerability scan ────────────────────────────────────────────────
@app.post("/analyze")
async def analyze(request: ScanRequest, http_request: Request):
    print(f"[DEBUG] /analyze called with path: {request.project_path}")
    path = request.project_path.strip()
    
    # Handle DB-stored projects
    cleanup_path = None
    if path.startswith("db://"):
        file_id = path.replace("db://", "")
        print(f"[DEBUG] [Analyze] Fetching project from DB: {file_id}")
        
        if not db_manager.db_manager:
             raise HTTPException(503, "Database manager not initialized")
        
        file_record = await db_manager.db_manager.get_file(file_id)
        if not file_record:
             raise HTTPException(404, "Project file not found in database")
        
        # Extract metadata (filename)
        project_name = "Uploaded Project"
        try:
            meta = file_record.get("metadata")
            if isinstance(meta, str):
                meta = json.loads(meta)
            if meta and "filename" in meta:
                project_name = meta["filename"]
        except:
             pass

        try:
             # Create temp workspace
             session_id = str(uuid.uuid4())
             ws_path = get_workspace_path(session_id)
             zip_path = os.path.join(ws_path, "project.zip")
             
             # Write content
             with open(zip_path, "wb") as f:
                 f.write(file_record["content"])
                 
             # Extract
             with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(ws_path)
             
             os.remove(zip_path)
             cleanup_path = ws_path
             
             # Adjust root if simple folder
             items = [i for i in os.listdir(ws_path) if i != '__MACOSX' and not i.startswith('.')]
             if len(items) == 1 and os.path.isdir(os.path.join(ws_path, items[0])):
                 path = os.path.join(ws_path, items[0])
             else:
                 path = ws_path
             print(f"[DEBUG] [Analyze] Extracted to: {path}")
             
        except Exception as e:
            print(f"[DEBUG] [Analyze] Extraction failed: {e}")
            raise HTTPException(500, f"Failed to extract project from DB: {e}")

    if not os.path.isdir(path):
        print(f"[DEBUG] [Analyze] Directory not found: {path}")
        raise HTTPException(400, f"Not a directory: {path}")

    # --- Run Analysis ---
    print(f"[DEBUG] [Analyze] Scanning directory: {path}")
    # from engine import scan_directory (ensure this is imported at top)
    findings = scan_directory(path)

    if cleanup_path: 
        # Normalize findings to be relative to the cleanup_path (temp workspace)
        # We need this so that we can retrieve files from the DB zip later, 
        # and to avoid showing ugly absolute temp paths in the UI.
        
        # Always relative to the extraction root (zip root) matches zip structure best
        root_for_rel = cleanup_path
        
        for f in findings:
            full_f = f.get("file", "")
            if full_f.startswith(root_for_rel):
                # Relativize
                rel = os.path.relpath(full_f, start=root_for_rel)
                f["file"] = rel.replace("\\", "/") # Normalize separators
            elif full_f.startswith(cleanup_path):
                rel = os.path.relpath(full_f, start=cleanup_path)
                f["file"] = rel.replace("\\", "/")

    print(f"[DEBUG] [Analyze] Scan complete. Found {len(findings)} findings.")

    # restore original db:// path in the result object if it was a db project
    # so we know to fetch from DB later
    result_path = request.project_path if request.project_path.startswith("db://") else path
    
    # Determine project name
    final_project_name = "Project"
    if request.project_path.startswith("db://"):
        # We might have set project_name above
        if 'project_name' in locals():
            final_project_name = project_name
    else:
        final_project_name = os.path.basename(path.rstrip('/\\')) or path

    result = {
        "timestamp": datetime.now().isoformat(),
        "path": result_path, 
        "project_name": final_project_name, 
        "total_findings": len(findings),
        "findings": findings,
        "is_db_project": request.project_path.startswith("db://")
    }
    
    # Cleanup temp workspace if used
    if cleanup_path:
        try:
            shutil.rmtree(cleanup_path, ignore_errors=True)
            print(f"[DEBUG] [Analyze] Cleaned up temp workspace: {cleanup_path}")
        except Exception as e:
            print(f"[DEBUG] [Analyze] Failed to cleanup temp workspace: {e}")

    _last_results["analyze"] = result

    # Attempt to save to DB automatically for authenticated users
    try:
        print("[DEBUG] [Analyze] Checking authentication for auto-save...")
        token = await _get_token_from_request(http_request)
        user_id = token.get("sub")
        print(f"[DEBUG] [Analyze] Authenticated user: {user_id}")
        
        scan_id = str(uuid.uuid4())
        payload = {"id": scan_id, "owner_id": user_id, "project_path": result_path, "results": json.dumps(result)}

        print("[DEBUG] [Analyze] Requesting DB engine...")
        target = await db_manager.db_manager.get_engine_for_write(0)
        if target:
            engine, idx = target
            print(f"[DEBUG] [Analyze] Got engine index {idx}. Inserting scan...")
            try:
                await db_manager.db_manager.insert_scan(engine, payload)
                print(f"[DEBUG] [Scan] Saved scan {scan_id} owner={user_id} to DB idx={idx}")
                result["saved_to_db"] = True
                result["scan_id"] = scan_id
            except Exception as e:
                print(f"[DEBUG] [Scan][DB] Failed to insert scan: {e}")
                result["saved_to_db"] = False
                result["save_error"] = str(e)
        else:
            print("[DEBUG] [Scan][DB] No DB available for write")
            result["saved_to_db"] = False
            result["save_error"] = "No DB available for write"
    except HTTPException:
        # Unauthenticated - do not auto-save
        print("[DEBUG] [Scan] unauthenticated request; skipping save")
        result["saved_to_db"] = False
        result["save_error"] = "unauthenticated"
    except Exception as e:
        # Database error or other failure
        print(f"[DEBUG] [Scan][Error] Unexpected error while saving scan: {e}")
        result["saved_to_db"] = False
        result["save_error"] = str(e)

    return result


# ─── Save the most recent analyze result as a persistent scan (requires auth)
import json
import uuid
from auth import _get_token_from_request

@app.post("/save_scan")
async def save_scan(request: Request):
    # ensure user authenticated
    token = await _get_token_from_request(request)
    user_id = token.get("sub")

    scan = _last_results.get("analyze")
    if not scan:
        raise HTTPException(status_code=400, detail="No recent analysis to save")

    scan_id = str(uuid.uuid4())
    payload = {"id": scan_id, "owner_id": user_id, "project_path": scan.get("path"), "results": json.dumps(scan)}

    target = await db_manager.db_manager.get_engine_for_write(0)
    if not target:
        raise HTTPException(status_code=507, detail="No DB with available space to save scan")
    engine, idx = target
    await db_manager.db_manager.insert_scan(engine, payload)
    return {"ok": True, "id": scan_id}


@app.get("/scans")
async def list_scans(request: Request):
    # Enforce strict filtering by authenticated user
    try:
        token = await _get_token_from_request(request)
        user_id = token.get("sub")
    except Exception:
        # If no user is logged in, return empty list or unauthorized
        raise HTTPException(status_code=401, detail="Authentication required to view history")

    scans = await db_manager.db_manager.list_scans(owner_id=user_id)
    
    # return light summary
    out = []
    for s in scans:
        results = s.get("results")
        try:
            results_json = results if isinstance(results, dict) else json.loads(results)
        except Exception:
            results_json = {}
        out.append({
            "id": s.get("id"),
            "owner_id": s.get("owner_id"),
            "project_path": s.get("project_path"),
            "project_name": results_json.get("project_name"),
            "created_at": s.get("created_at"),
            "total_findings": results_json.get("total_findings") if results_json else None
        })
    return out


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    s = await db_manager.db_manager.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    results = s.get("results")
    if not isinstance(results, dict):
        try:
            results = json.loads(results)
        except Exception:
            results = {}
    return {"id": s.get("id"), "owner_id": s.get("owner_id"), "project_path": s.get("project_path"), "created_at": s.get("created_at"), "results": results}


@app.get("/scans/{scan_id}/files")
async def scan_files(scan_id: str):
    s = await db_manager.db_manager.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    results = s.get("results")
    if not isinstance(results, dict):
        try:
            results = json.loads(results)
        except Exception:
            results = {}
    findings = results.get("findings", [])
    files = {}
    for f in findings:
        path = f.get("file")
        files.setdefault(path, {"count": 0, "findings": []})
        files[path]["count"] += 1
        files[path]["findings"].append(f)
    out = []
    for path, v in files.items():
        out.append({"path": path, "count": v["count"]})
    return out


@app.get("/scans/{scan_id}/files/details")
async def scan_file_details(scan_id: str, file_path: str):
    s = await db_manager.db_manager.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    results = s.get("results")
    if not isinstance(results, dict):
        try:
            results = json.loads(results)
        except Exception:
            results = {}
    
    findings = results.get("findings", [])
    # file_path argument might be relative now (if analyze normalized it) or absolute (old scans)
    # We should match fuzzily or assume exact match if frontend sends what it got from findings
    
    # Filter findings for this file
    file_findings = [f for f in findings if f.get("file") == file_path]
    if not file_findings:
        # Try normalizing slashes just in case
        norm_path = file_path.replace("\\", "/")
        file_findings = [f for f in findings if f.get("file").replace("\\", "/") == norm_path]

    lines = []
    
    # Strategy 1: If project_path is db://, fetch content from stored zip
    project_path = s.get("project_path") or ""
    if project_path.startswith("db://"):
        file_id = project_path.replace("db://", "")
        file_record = await db_manager.db_manager.get_file(file_id)
        if file_record and file_record.get("content"):
             import io
             try:
                 with zipfile.ZipFile(io.BytesIO(file_record["content"])) as zip_ref:
                     # zip paths usually use forward slash
                     # Attempt 1: Exact relative path (normalized to /)
                     target_name = file_path.replace("\\", "/")
                     
                     # Check if zip has top-level folder logic that we handled in analyze
                     # It's hard to know exactly what the relative root was without re-analyzing.
                     # But efficiently, we can check if target_name is in namelist, or if 
                     # we need to prefix/unprefix it.
                     
                     all_names = zip_ref.namelist()
                     
                     # Simple heuristic: find a file in the zip that ends with our target path
                     candidate = None
                     for name in all_names:
                         if name.endswith(target_name) or name == target_name:
                             # verify it's a suffix match with path separator check to avoid partial filename match
                             if name == target_name or name.endswith("/" + target_name):
                                 # Prefer exact match or the one with the shortest path (closest to root) if ambiguity?
                                 # Usually if we stripped a top-level dir, the zip entry is "TopDir/manage.py" and we have "manage.py"
                                 candidate = name
                                 break
                     
                     if candidate:
                        with zip_ref.open(candidate) as myfile:
                            content_bytes = myfile.read()
                            # decode assuming utf-8
                            lines = content_bytes.decode('utf-8', errors='replace').splitlines()
             except Exception as e:
                 print(f"[ScanDetail] Failed to read from zip: {e}")
                 pass

    # Strategy 2: If lines still empty, try local file read (backward compatibility for old scans or local scans)
    if not lines and not project_path.startswith("db://"):
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                lines = [line.rstrip('\n') for line in fh]
        except Exception:
            pass

    # Process lines into structure
    for f in file_findings:
        ln = int(f.get("line") or 0)

        # snippet context
        start = max(1, ln - 3)
        end = min(len(lines), ln + 3)
        context = []
        for i in range(start, end + 1):
            if 0 <= i-1 < len(lines):
                code_line = lines[i - 1]
                context.append({"line": i, "code": code_line, "highlight": (i == ln)})
        f["snippet"] = context

        # full file content (line-by-line) with highlight on vulnerability line
        full = []
        for i, raw in enumerate(lines, start=1):
            full.append({"line": i, "code": raw, "highlight": (i == ln)})
        f["full"] = full

    return {"file": file_path, "findings": file_findings}

# ─── 2. Data access (memory + optional AST) ───────────────────────────────
@app.post("/data_access")
async def data_access(request: DataAccessRequest):
    path = request.project_path.strip()
    if not os.path.isdir(path):
        raise HTTPException(400, f"Not a directory: {path}")

    mem_data = memory_space_data(path)

    ast_data = None
    if request.include_ast:
        ast_data = ast_view(path)

    result = {
        "timestamp": datetime.now().isoformat(),
        "path": path,
        "memory_space_data": mem_data,
        "ast_view": ast_data if request.include_ast else {"note": "AST view skipped (enable include_ast to include)"}
    }

    _last_results["data_access"] = result
    return result

# ─── 3. CVE + Gemini correlated analysis ──────────────────────────────────
@app.post("/rag_cve")
async def rag_cve(request: RAGRequest):
    try:
        project_path = request.project_path.strip()
        if not os.path.isdir(project_path):
            raise HTTPException(400, f"Not a directory: {project_path}")

        # 1. Run scanner to get project-specific context
        print(f"[RAG] Scanning project: {project_path}")
        scanner_findings = scan_directory(project_path)
        findings_summary = summarize_scanner_findings(scanner_findings)
        print(f"[RAG] Scanner found {len(scanner_findings)} issues")

        # 2. Fetch latest KEV catalog
        kev_data = fetch_kev()
        if not kev_data:
            raise HTTPException(503, "Failed to fetch CISA KEV catalog")

        vulnerabilities = kev_data.get("vulnerabilities", kev_data)
        if isinstance(vulnerabilities, dict):
            vulnerabilities = vulnerabilities.get("vulnerabilities", [])

        # 3. Filter recent/urgent CVEs
        now = datetime.utcnow()
        recent_threshold = now - timedelta(days=request.days_recent)
        soon_due_threshold = now + timedelta(days=request.days_urgent)

        relevant_cves = []
        for v in vulnerabilities:
            try:
                added = datetime.strptime(v.get("dateAdded", "1900-01-01"), "%Y-%m-%d")
                due_str = v.get("dueDate")
                due = datetime.strptime(due_str, "%Y-%m-%d") if due_str else None

                if added >= recent_threshold or (due and due <= soon_due_threshold):
                    relevant_cves.append({
                        "cve": v.get("cveID", "N/A"),
                        "vendor": v.get("vendorProject", "N/A"),
                        "product": v.get("product", "N/A"),
                        "name": v.get("vulnerabilityName", "N/A"),
                        "added": v.get("dateAdded"),
                        "due": due_str or "N/A",
                        "action": v.get("requiredAction", "Apply updates"),
                        "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                        "notes": v.get("notes", "")
                    })
            except:
                continue

        print(f"[RAG] Found {len(relevant_cves)} recent/urgent CVEs")

        # 4. Prepare context strings
        kev_text = format_kev_text(relevant_cves, request.max_cves)

        # 5. Create correlated prompt
        prompt = f"""You are a senior cybersecurity analyst specializing in Python/Django security.

Current date: {datetime.now().strftime("%Y-%m-%d")}

Project scan results (static analysis):
{findings_summary}

Latest CISA Known Exploited Vulnerabilities (filtered recent/urgent):
{kev_text}

Task:
Correlate the detected issues in this specific codebase with the known exploited vulnerabilities above.

Focus especially on:
• Which KEV CVEs are **particularly dangerous** given what was already found?  
  (examples: shell=True usage → command injection exploits; pickle.load → deserialization RCE; weak hashes → crypto attacks)
• Realistic short-term risk (3–6 months) for this project in 2026
• Top 3–6 most relevant CVEs for this codebase — explain **why** they matter here
• Tailored immediate actions: patch versions, code changes, mitigations, monitoring — prioritized by scanner findings
• Overall trend: is exploitation in the Python ecosystem accelerating?

Be concise. Use bullet points. Quote CVE IDs and scanner findings when relevant.
Prioritize correlation over generic analysis.
"""

        print(f"[RAG] Sending correlated prompt to Gemini ({GEMINI_MODEL})...")

        # 6. Call Gemini
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )

        analysis_text = response.text.strip()

        # 7. Build and return result
        result = {
            "timestamp": datetime.now().isoformat(),
            "model": GEMINI_MODEL,
            "project_path": project_path,
            "scanner_issues_count": len(scanner_findings),
            "relevant_cves_count": len(relevant_cves),
            "analysis": analysis_text,
            "scanner_summary": findings_summary,
            "relevant_cves_sample": relevant_cves[:8]  # first 8 for reference
        }

        _last_results["rag_cve"] = result
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RAG/CVE analysis failed: {str(e)}")


# Serve built frontend if available
import os as _os
frontend_dist = _os.path.join(_os.path.dirname(__file__), "frontend", "dist")
if _os.path.isdir(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")


# If a request for the frontend's client-side auth callback hits the backend (common during dev or misconfiguration),
# provide a helpful redirect page so users still reach the correct frontend route.
@app.get("/auth-callback")
async def auth_callback_bridge():
    frontend = os.getenv("OAUTH_REDIRECT_BASE", "http://localhost:5173").rstrip('/')
    target = f"{frontend}/auth-callback?status=ok"
    print(f"[Server] Bridging /auth-callback -> {target}")
    # Serve a small HTML that navigates the browser to the frontend URL (preserves cookies set by backend)
    html = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>Authentication</title>
        <meta http-equiv="refresh" content="0; url={target}" />
        <script>window.location.replace({target!r});</script>
      </head>
      <body>
        <p>Redirecting to the application... If you are not redirected, <a href="{target}">click here</a>.</p>
      </body>
    </html>
    """
    return HTMLResponse(content=html, status_code=302, headers={"Location": target})

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    reload = os.environ.get("RELOAD", "false").lower() == "true"
    print("Starting FastAPI server...")
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=reload)