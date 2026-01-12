import os
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn
from typing import Dict, Any, List
from collections import Counter
import requests

# Your modules
from engine import scan_directory
from data_access import memory_space_data, ast_view

# ─── Gemini setup ──────────────────────────────────────────────────────────
from dotenv import load_dotenv
from google import genai

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY not found in environment or .env file")

client = genai.Client(api_key=GEMINI_API_KEY)
GEMINI_MODEL = "gemini-2.5-flash"

# ─── FastAPI app ───────────────────────────────────────────────────────────
app = FastAPI(
    title="Python Security & CVE Analysis API",
    description="Endpoints for code scanning, structure analysis and CVE intelligence",
    version="0.1.0"
)

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
async def analyze(request: ScanRequest):
    path = request.project_path.strip()
    if not os.path.isdir(path):
        raise HTTPException(400, f"Not a directory: {path}")

    findings = scan_directory(path)

    result = {
        "timestamp": datetime.now().isoformat(),
        "path": path,
        "total_findings": len(findings),
        "findings": findings
    }

    _last_results["analyze"] = result
    return result

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


if __name__ == "__main__":
    print("Starting FastAPI server...")
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)