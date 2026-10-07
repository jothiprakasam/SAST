import requests
import json
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from collections import Counter
from typing import Optional, Dict, Any, List

try:
    from google import genai
except ImportError:
    genai = None

# Import the scanner from engine.py
from engine import scan_directory

load_dotenv()

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_MODEL = "gemini-2.5-flash"
OUTPUT_JSON_FILE = "gemini_kev_analysis.json"
DEFAULT_PROJECT_PATH = "./project_test"


def summarize_findings(findings: List[dict]) -> str:
    """Create a concise summary of scanner findings for Gemini context."""
    if not findings:
        return "No vulnerabilities or issues detected by the static scanner."

    severity_count = Counter(f.get("severity", "MEDIUM") for f in findings)
    category_count = Counter(f.get("category", "Unknown") for f in findings)

    summary = "Static code scanner findings summary:\n"
    summary += f"Total issues found: {len(findings)}\n"
    summary += "Severity distribution:\n"
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in severity_count:
            summary += f"  - {sev}: {severity_count[sev]}\n"

    summary += "\nTop categories:\n"
    for cat, cnt in category_count.most_common(8):
        summary += f"  - {cat}: {cnt} occurrences\n"

    high_critical = [f for f in findings if f.get("severity") in ["HIGH", "CRITICAL"]][:6]
    if high_critical:
        summary += "\nExamples of HIGH/CRITICAL issues:\n"
        for f in high_critical:
            fname = os.path.basename(f.get("file", ""))
            summary += f"  - {f.get('category')} ({f.get('cwe', '')}) in {fname}:{f.get('line')} → {f.get('message')}\n"

    return summary


def fetch_kev_data() -> Optional[dict]:
    """Fetch CISA Known Exploited Vulnerabilities catalog with timeout handling."""
    try:
        r = requests.get(KEV_URL, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[KEV] Error fetching CISA KEV catalog: {e}")
        return None


def run_cve_analysis(
    project_path: str = DEFAULT_PROJECT_PATH,
    api_key: Optional[str] = None,
    model: str = DEFAULT_MODEL,
    max_cves: int = 45,
    days_recent: int = 60,
    days_urgent: int = 30
) -> Dict[str, Any]:
    """
    Correlates static scanner results against live CISA KEV data using Gemini AI.
    """
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        return {
            "error": "GEMINI_API_KEY is not configured. Please supply an API key in settings or in your .env file.",
            "success": False
        }

    if genai is None:
        return {
            "error": "google-genai package is not installed.",
            "success": False
        }

    client = genai.Client(api_key=key)

    # 1. Run static scanner
    findings = scan_directory(project_path) if os.path.isdir(project_path) else []
    findings_summary = summarize_findings(findings)

    # 2. Fetch KEV
    kev_data = fetch_kev_data()
    if not kev_data:
        return {
            "error": "Failed to fetch CISA Known Exploited Vulnerabilities catalog.",
            "success": False
        }

    vulnerabilities = kev_data.get("vulnerabilities", [])
    if isinstance(vulnerabilities, dict):
        vulnerabilities = vulnerabilities.get("vulnerabilities", [])

    # 3. Filter recent/urgent CVEs
    now = datetime.utcnow()
    recent_threshold = now - timedelta(days=days_recent)
    soon_due_threshold = now + timedelta(days=days_urgent)

    relevant = []
    for v in vulnerabilities:
        try:
            added = datetime.strptime(v.get("dateAdded", "1900-01-01"), "%Y-%m-%d")
            due_str = v.get("dueDate")
            due = datetime.strptime(due_str, "%Y-%m-%d") if due_str else None

            if added >= recent_threshold or (due and due <= soon_due_threshold):
                relevant.append({
                    "cve": v.get("cveID", "N/A"),
                    "vendor": v.get("vendorProject", "N/A"),
                    "product": v.get("product", "N/A"),
                    "name": v.get("vulnerabilityName", "N/A"),
                    "added": v.get("dateAdded"),
                    "due": due_str or "N/A",
                    "action": v.get("requiredAction", "Apply updates / mitigate"),
                    "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes": v.get("notes", "")
                })
        except Exception:
            continue

    # 4. Context string
    kev_text = "CISA Known Exploited Vulnerabilities (recent/urgent):\n\n"
    for item in relevant[:max_cves]:
        kev_text += f"• {item['cve']} | {item['vendor']} {item['product']} — {item['name']}\n"
        kev_text += f"  Added: {item['added']} | Due: {item['due']} | Ransomware: {item['ransomware']}\n"
        kev_text += f"  Action: {item['action']}\n"
        if item.get('notes'):
            kev_text += f"  Notes: {item['notes'][:180]}...\n"
        kev_text += "\n"

    # 5. Prompt
    prompt = f"""You are a senior cybersecurity analyst specializing in Python security and secure code audits.

Current date: {datetime.now().strftime("%Y-%m-%d")}

Project scan results (static code analysis):
{findings_summary}

Latest CISA Known Exploited Vulnerabilities (recent/urgent):
{kev_text}

Analyze this information with focus on:
- Which of these KEV CVEs are **especially relevant or dangerous** given the vulnerabilities detected in this project?
  (e.g., if command injection was found, highlight shell/RCE exploits; if hardcoded secrets, highlight credential theft)
- Realistic short-term risk level for this codebase
- Top 3-5 most critical CVEs for this project and explain why
- Concrete immediate remediations (code refactors, dependency updates, security headers)
- Ecosystem trends in Python vulnerability exploitation

Be structured, concise, and use clear markdown headings and bullet points.
"""

    try:
        response = client.models.generate_content(
            model=model,
            contents=prompt
        )
        analysis_text = response.text.strip()

        return {
            "success": True,
            "timestamp": datetime.now().isoformat(),
            "project_path": project_path,
            "model_used": model,
            "scanner_issues_count": len(findings),
            "relevant_cves_count": len(relevant),
            "total_kev_catalog_size": len(vulnerabilities),
            "analysis": analysis_text,
            "scanner_summary": findings_summary,
            "relevant_cves_sample": relevant[:10]
        }
    except Exception as e:
        return {
            "error": f"Gemini API request failed: {str(e)}",
            "success": False
        }


def main(project_path: str = DEFAULT_PROJECT_PATH):
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        print("Warning: GEMINI_API_KEY not found in environment or .env file.")
        return
    res = run_cve_analysis(project_path=project_path, api_key=key)
    if res.get("success"):
        print("\nAnalysis Result:\n")
        print(res.get("analysis"))
        with open(OUTPUT_JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
        print(f"\nSaved to {OUTPUT_JSON_FILE}")
    else:
        print(f"Error: {res.get('error')}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run KEV + Gemini analysis with project scanner context")
    parser.add_argument("--path", type=str, default=DEFAULT_PROJECT_PATH, help="Path to project directory")
    args = parser.parse_args()
    main(project_path=args.path)