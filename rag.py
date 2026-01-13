import requests
import json
from datetime import datetime, timedelta
from google import genai
import os
from dotenv import load_dotenv
from collections import Counter

# Import the scanner from engine.py
from engine import scan_directory

# ────────────────────────────────────────────────
#  Load environment variables (API key from .env)
# ────────────────────────────────────────────────
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("Error: GEMINI_API_KEY not found in .env file or environment variables.")
    print("Please create a .env file with: GEMINI_API_KEY=your-key-here")
    exit(1)

# ────────────────────────────────────────────────
#  CONFIG
# ────────────────────────────────────────────────
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

client = genai.Client(api_key=GEMINI_API_KEY)

MODEL = "gemini-2.5-flash"  # or "gemini-2.5-pro" for better reasoning

OUTPUT_JSON_FILE = "gemini_kev_analysis.json"

DEFAULT_PROJECT_PATH = "./project_test"


def summarize_findings(findings):
    """Create a concise summary of scanner findings for Gemini context."""
    if not findings:
        return "No vulnerabilities or issues detected by the static scanner."

    severity_count = Counter(f["severity"] for f in findings)
    category_count = Counter(f["category"] for f in findings)

    summary = "Static code scanner findings summary:\n"
    summary += f"Total issues found: {len(findings)}\n"
    summary += "Severity distribution:\n"
    for sev, cnt in sorted(severity_count.items(), key=lambda x: ["INFO","LOW","MEDIUM","HIGH","CRITICAL"].index(x[0])):
        summary += f"  - {sev}: {cnt}\n"

    summary += "\nTop categories (most frequent):\n"
    for cat, cnt in category_count.most_common(8):
        summary += f"  - {cat}: {cnt} occurrences\n"

    # Add a few concrete high/critical examples (limited)
    high_critical = [f for f in findings if f["severity"] in ["HIGH", "CRITICAL"]][:5]
    if high_critical:
        summary += "\nExamples of HIGH/CRITICAL issues:\n"
        for f in high_critical:
            summary += f"  - {f['category']} in {os.path.basename(f['file'])}:{f['line']} → {f['message']}\n"

    return summary


def main(project_path: str = DEFAULT_PROJECT_PATH):
    # ────────────────────────────────────────────────
    # 1. Run static scanner (engine.py)
    # ────────────────────────────────────────────────
    print(f"[SCANNER] Analyzing project: {project_path}")
    if not os.path.isdir(project_path):
        print(f"Error: Directory not found: {project_path}")
        return

    findings = scan_directory(project_path)
    findings_summary = summarize_findings(findings)
    print(f"[SCANNER] Found {len(findings)} issues")

    # ────────────────────────────────────────────────
    # 2. Fetch KEV Catalog
    # ────────────────────────────────────────────────
    print("[KEV] Fetching CISA Known Exploited Vulnerabilities...")
    try:
        r = requests.get(KEV_URL, timeout=15)
        r.raise_for_status()
        kev_data = r.json()
        print(f"KEV catalog fetched (Last-Modified: {r.headers.get('Last-Modified', 'unknown')})")
    except Exception as e:
        print(f"Error fetching KEV: {e}")
        return

    vulnerabilities = kev_data.get("vulnerabilities", kev_data)
    if isinstance(vulnerabilities, dict):
        vulnerabilities = vulnerabilities.get("vulnerabilities", [])

    # ────────────────────────────────────────────────
    # 3. Filter recent/urgent CVEs
    # ────────────────────────────────────────────────
    now = datetime.utcnow()
    recent_threshold = now - timedelta(days=60)
    soon_due_threshold = now + timedelta(days=30)

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
        except:
            continue

    print(f"[KEV] Found {len(relevant)} recent/urgent entries (total {len(vulnerabilities)})")

    # ────────────────────────────────────────────────
    # 4. Prepare context for Gemini
    # ────────────────────────────────────────────────
    kev_text = "CISA Known Exploited Vulnerabilities (recent/urgent):\n\n"
    for item in relevant[:45]:
        kev_text += f"• {item['cve']} | {item['vendor']} {item['product']} — {item['name']}\n"
        kev_text += f"  Added: {item['added']} | Due: {item['due']} | Ransomware: {item['ransomware']}\n"
        kev_text += f"  Action: {item['action']}\n"
        if item['notes']:
            kev_text += f"  Notes: {item['notes'][:180]}...\n"
        kev_text += "\n"

    # ────────────────────────────────────────────────
    # 5. Enhanced prompt with scanner context
    # ────────────────────────────────────────────────
    prompt = f"""You are a senior cybersecurity analyst specializing in Python/Django applications.

Current date: {datetime.now().strftime("%Y-%m-%d")}

Project scan results:
{findings_summary}

Latest CISA Known Exploited Vulnerabilities (recent/urgent):
{kev_text}

Analyze this information with focus on:

- Which of these KEV CVEs are **especially relevant or dangerous** given the vulnerabilities already detected in this specific project?
  (Example: if insecure deserialization / pickle was found → highlight related RCE CVEs; if weak hashes → highlight crypto degradation CVEs)
- Python/Django ecosystem impact (urllib3, requests, cryptography, aiohttp, gunicorn, uvicorn, etc.)
- Entries linked to ransomware or very short patching deadlines
- Realistic short-term risk level (next 3–6 months) for this codebase in 2026
- Top 3–6 most relevant CVEs for this project — explain **why** they matter here
- Tailored immediate actions (patch versions, code changes, mitigations, monitoring) considering the detected issues

Be concise, evidence-based, use bullet points.
Quote CVE IDs, file paths or issue types from the scan when relevant.
Prioritize correlation between static findings and known exploited vulnerabilities.
"""

    print(f"[GEMINI] Sending enhanced prompt ({MODEL})...")

    try:
        response = client.models.generate_content(
            model=MODEL,
            contents=prompt
        )

        analysis_text = response.text.strip()

        print("\n" + "═" * 90)
        print(f"Gemini Correlated Analysis ({datetime.now().strftime('%Y-%m-%d %H:%M IST')})")
        print("═" * 90 + "\n")
        print(analysis_text)

        # ────────────────────────────────────────────────
        # 6. Save result to JSON
        # ────────────────────────────────────────────────
        result_data = {
            "timestamp_ist": datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),
            "timestamp_utc": datetime.utcnow().isoformat(),
            "project_path": project_path,
            "model_used": MODEL,
            "scanner_issues_count": len(findings),
            "relevant_cves_count": len(relevant),
            "total_kev_entries": len(vulnerabilities),
            "analysis": analysis_text,
            "scanner_summary": findings_summary,
            "relevant_cves": relevant[:45]
        }

        with open(OUTPUT_JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)

        print(f"\nFull analysis (with scanner correlation) saved to: {OUTPUT_JSON_FILE}")

    except Exception as e:
        print(f"Gemini API error: {e}")
        if "rate limit" in str(e).lower():
            print("→ Rate limit hit. Wait a few minutes or check quota.")
        elif "authentication" in str(e).lower() or "invalid" in str(e).lower():
            print("→ Check GEMINI_API_KEY in .env file.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run KEV + Gemini analysis with project scanner context")
    parser.add_argument("--path", type=str, default=DEFAULT_PROJECT_PATH,
                        help=f"Path to the project directory (default: {DEFAULT_PROJECT_PATH})")
    args = parser.parse_args()

    main(project_path=args.path)