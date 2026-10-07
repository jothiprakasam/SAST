// Aegis SAST Frontend Application Logic

const API_BASE = window.location.origin;

let state = {
  currentTab: 'project',
  fileSubMode: 'editor',
  lastProjectResult: null,
  lastFileResult: null,
  explorerCurrentPath: '.',
  rulesList: [],
  geminiConfigured: false
};

// Preset Vulnerability Samples for 1-click testing
const PRESETS = {
  cmdi: `# Vulnerability Example: Remote OS Command Injection (CWE-78)
import subprocess
import os

def ping_server(host_ip):
    # CRITICAL: shell=True with unvalidated user input enables command chaining (e.g. host_ip = "127.0.0.1; whoami")
    command = f"ping -c 1 {host_ip}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
`,
  sqli: `# Vulnerability Example: SQL Injection (CWE-89)
import sqlite3

def find_user_records(user_input):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # HIGH: String concatenation into SQL query allows authentication bypass and data exfiltration
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()
`,
  pickle: `# Vulnerability Example: Insecure Deserialization (CWE-502)
import pickle

def restore_session_state(raw_session_bytes):
    # HIGH: pickle.loads executed on untrusted user data can execute arbitrary Python bytecode / RCE
    state = pickle.loads(raw_session_bytes)
    return state
`,
  secrets: `# Vulnerability Example: Hardcoded Secrets (CWE-798)
# HIGH: Hardcoding production credentials or keys in source code leads to credential leaks in version control
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "SuperSecretProductionPassword2026!"
STRIPE_API_TOKEN = "sk_live_51Nz8ABCDEF1234567890abcdef"
`,
  crypto: `# Vulnerability Example: Weak Cryptography (CWE-327)
import hashlib

def calculate_checksum(file_content):
    # MEDIUM: MD5 has known collision attacks and should never be used for security purposes
    hasher = hashlib.md5()
    hasher.update(file_content)
    return hasher.hexdigest()
`,
  tempfile: `# Vulnerability Example: Insecure Temporary File (CWE-377)
import tempfile

def write_staging_data(content):
    # HIGH: tempfile.mktemp() creates a filename before file creation, leading to race condition attacks (TOCTOU)
    temp_path = tempfile.mktemp(prefix="staging_")
    with open(temp_path, "w") as f:
        f.write(content)
    return temp_path
`,
  debug: `# Vulnerability Example: Insecure Production Configuration (CWE-489)
# MEDIUM: Running with DEBUG = True in production leaks detailed stack traces and system secrets
DEBUG = True
SECRET_KEY = "django-insecure-temp-key-for-local-testing"
ALLOWED_HOSTS = ["*"]
`
};

// ─── Initialization ─────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initLucide();
  checkHealth();
  loadRulesCatalog();
  updateGutter();

  // Populate default preset
  const editor = document.getElementById("code-editor");
  if (editor && !editor.value) {
    editor.value = PRESETS.cmdi;
    updateGutter();
  }

  // Keyboard shortcut Ctrl+Enter to scan
  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      if (state.currentTab === "project") {
        startProjectScan();
      } else if (state.currentTab === "file") {
        scanCodeSnippet();
      }
    }
  });
});

function initLucide() {
  if (window.lucide && window.lucide.createIcons) {
    window.lucide.createIcons();
  }
}

// ─── Health & Connection ───────────────────────────────────────────────────

async function checkHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (res.ok) {
      const data = await res.json();
      const badge = document.getElementById("status-badge");
      const text = document.getElementById("status-text");
      badge.className = "flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-950/70 border border-emerald-800 text-emerald-400";
      text.innerText = "Engine Ready";
      state.geminiConfigured = data.gemini_configured;
    }
  } catch (err) {
    const badge = document.getElementById("status-badge");
    const text = document.getElementById("status-text");
    badge.className = "flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-rose-950/70 border border-rose-800 text-rose-400";
    text.innerText = "Server Disconnected";
  }
}

// ─── Navigation Tabs ───────────────────────────────────────────────────────

function switchMainTab(tabName) {
  state.currentTab = tabName;
  const tabs = ['project', 'file', 'ast', 'rag', 'rules'];
  
  tabs.forEach(t => {
    const el = document.getElementById(`tab-${t}`);
    const btn = document.getElementById(`nav-btn-${t}`);
    if (t === tabName) {
      el.classList.remove('hidden');
      if (btn) {
        btn.className = "px-4 py-1.5 rounded-lg text-sm font-medium transition flex items-center space-x-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30";
      }
    } else {
      el.classList.add('hidden');
      if (btn) {
        btn.className = "px-4 py-1.5 rounded-lg text-sm font-medium transition flex items-center space-x-2 text-slate-300 hover:text-white hover:bg-slate-800";
      }
    }
  });
  initLucide();
}

function switchFileSubMode(mode) {
  state.fileSubMode = mode;
  const modes = ['editor', 'path', 'upload'];

  modes.forEach(m => {
    const el = document.getElementById(`file-mode-${m}`);
    const btn = document.getElementById(`file-sub-${m}`);
    if (m === mode) {
      el.classList.remove('hidden');
      btn.className = "px-3 py-1.5 rounded-md bg-cyan-500/20 text-cyan-400 border border-cyan-500/30";
    } else {
      el.classList.add('hidden');
      btn.className = "px-3 py-1.5 rounded-md text-slate-400 hover:text-white";
    }
  });
  initLucide();
}

// ─── TAB 1: LOCAL PROJECT SCAN ─────────────────────────────────────────────

function setProjectPath(path) {
  document.getElementById("project-path-input").value = path;
}

async function startProjectScan() {
  const input = document.getElementById("project-path-input");
  const projectPath = input.value.trim();
  if (!projectPath) {
    showToast("Please specify a project path.", "warning");
    return;
  }

  const loading = document.getElementById("project-scan-loading");
  const resultsContainer = document.getElementById("project-results-container");
  loading.classList.remove("hidden");
  resultsContainer.classList.add("hidden");

  try {
    const res = await fetch(`${API_BASE}/api/scan/project`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project_path: projectPath })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to scan project");
    }

    const data = await res.json();
    state.lastProjectResult = data;
    renderProjectResults(data);
    showToast(`Scan complete: Found ${data.total_findings} issues`, "success");
  } catch (err) {
    showToast(err.message, "error");
  } finally {
    loading.classList.add("hidden");
  }
}

async function handleZipUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append("file", file);

  const loading = document.getElementById("project-scan-loading");
  const resultsContainer = document.getElementById("project-results-container");
  loading.classList.remove("hidden");
  resultsContainer.classList.add("hidden");

  try {
    const res = await fetch(`${API_BASE}/api/scan/upload`, {
      method: "POST",
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Upload scan failed");
    }

    const data = await res.json();
    state.lastProjectResult = data;
    renderProjectResults(data);
    showToast(`Zip scan complete: Found ${data.total_findings} issues`, "success");
  } catch (err) {
    showToast(err.message, "error");
  } finally {
    loading.classList.add("hidden");
  }
}

function renderProjectResults(data) {
  const resultsContainer = document.getElementById("project-results-container");
  resultsContainer.classList.remove("hidden");

  // Health Score & Grade
  const score = data.score !== undefined ? data.score : 100;
  const scoreText = document.getElementById("proj-score-text");
  const gradeText = document.getElementById("proj-grade-text");

  scoreText.innerText = `${score} / 100`;
  let grade = "Grade A";
  let colorClass = "text-emerald-400";
  if (score < 50) { grade = "Grade F"; colorClass = "text-rose-400"; }
  else if (score < 70) { grade = "Grade D"; colorClass = "text-orange-400"; }
  else if (score < 80) { grade = "Grade C"; colorClass = "text-amber-400"; }
  else if (score < 90) { grade = "Grade B"; colorClass = "text-cyan-400"; }

  scoreText.className = `text-3xl font-extrabold mt-1 ${colorClass}`;
  gradeText.innerHTML = `Rating: <span class="${colorClass} font-semibold">${grade}</span>`;

  // Counters
  document.getElementById("proj-total-findings").innerText = data.total_findings || 0;
  document.getElementById("proj-files-impacted").innerText = `Across ${data.files_with_issues_count || 1} files`;

  const stats = data.stats || {};
  const critHigh = (stats.CRITICAL || 0) + (stats.HIGH || 0);
  document.getElementById("proj-crit-high-count").innerText = critHigh;

  // Severity Distribution Bar
  const total = data.total_findings || 1;
  const cP = ((stats.CRITICAL || 0) / total) * 100;
  const hP = ((stats.HIGH || 0) / total) * 100;
  const mP = ((stats.MEDIUM || 0) / total) * 100;
  const lP = ((stats.LOW || 0) / total) * 100;
  const iP = ((stats.INFO || 0) / total) * 100;

  document.getElementById("bar-crit").style.width = `${cP}%`;
  document.getElementById("bar-high").style.width = `${hP}%`;
  document.getElementById("bar-med").style.width = `${mP}%`;
  document.getElementById("bar-low").style.width = `${lP}%`;
  document.getElementById("bar-info").style.width = `${iP}%`;

  document.getElementById("proj-severity-stats").innerText =
    `${stats.CRITICAL || 0} Critical • ${stats.HIGH || 0} High • ${stats.MEDIUM || 0} Medium • ${stats.LOW || 0} Low • ${stats.INFO || 0} Info`;

  // Populate Categories Filter Dropdown
  const catFilter = document.getElementById("proj-category-filter");
  catFilter.innerHTML = '<option value="ALL">All Categories</option>';
  if (data.categories_breakdown) {
    for (const [cat, cnt] of Object.entries(data.categories_breakdown)) {
      catFilter.innerHTML += `<option value="${cat}">${cat} (${cnt})</option>`;
    }
  }

  filterProjectFindings();
  initLucide();
}

function filterProjectFindings() {
  if (!state.lastProjectResult) return;

  const query = document.getElementById("proj-search-input").value.toLowerCase();
  const sevFilter = document.getElementById("proj-severity-filter").value;
  const catFilter = document.getElementById("proj-category-filter").value;

  const findings = state.lastProjectResult.findings || [];
  const filtered = findings.filter(f => {
    if (sevFilter !== "ALL" && f.severity !== sevFilter) return false;
    if (catFilter !== "ALL" && f.category !== catFilter) return false;
    if (query) {
      const matchMsg = (f.message || "").toLowerCase().includes(query);
      const matchFile = (f.file || "").toLowerCase().includes(query);
      const matchCat = (f.category || "").toLowerCase().includes(query);
      const matchCwe = (f.cwe || "").toLowerCase().includes(query);
      return matchMsg || matchFile || matchCat || matchCwe;
    }
    return true;
  });

  const container = document.getElementById("proj-findings-list");
  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="card-glass p-8 text-center text-slate-500">
        <i data-lucide="shield-check" class="w-10 h-10 text-emerald-400 mx-auto mb-2"></i>
        <h4 class="text-sm font-semibold text-slate-300">No findings matched your criteria</h4>
        <p class="text-xs mt-1">Try resetting the search filters.</p>
      </div>
    `;
    initLucide();
    return;
  }

  container.innerHTML = filtered.map(f => createFindingCardHTML(f)).join("");
  initLucide();
}

// ─── TAB 2: SINGLE FILE SCAN ───────────────────────────────────────────────

function updateGutter() {
  const textarea = document.getElementById("code-editor");
  const gutter = document.getElementById("editor-gutter");
  if (!textarea || !gutter) return;

  const lines = textarea.value.split("\n").length;
  let gutterHTML = "";
  for (let i = 1; i <= Math.max(lines, 1); i++) {
    gutterHTML += `${i}<br>`;
  }
  gutter.innerHTML = gutterHTML;
}

function handleEditorTab(e) {
  if (e.key === "Tab") {
    e.preventDefault();
    const textarea = e.target;
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    textarea.value = textarea.value.substring(0, start) + "    " + textarea.value.substring(end);
    textarea.selectionStart = textarea.selectionEnd = start + 4;
    updateGutter();
  }
}

function loadPresetSample() {
  const select = document.getElementById("preset-select");
  const val = select.value;
  if (val && PRESETS[val]) {
    const editor = document.getElementById("code-editor");
    editor.value = PRESETS[val];
    updateGutter();
    showToast(`Loaded ${select.options[select.selectedIndex].text}`, "info");
  }
}

function clearEditor() {
  document.getElementById("code-editor").value = "";
  updateGutter();
}

function copyEditor() {
  const val = document.getElementById("code-editor").value;
  navigator.clipboard.writeText(val);
  showToast("Code copied to clipboard!", "success");
}

function setSingleFilePath(path) {
  document.getElementById("single-file-path-input").value = path;
}

async function scanCodeSnippet() {
  const code = document.getElementById("code-editor").value;
  if (!code.trim()) {
    showToast("Please enter or paste Python code.", "warning");
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/scan/code`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: code, filename: "snippet.py" })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Scan snippet failed");
    }

    const data = await res.json();
    state.lastFileResult = data;
    renderFileResults(data);
    showToast(`Snippet scanned: ${data.total_findings} issues found`, "success");
  } catch (err) {
    showToast(err.message, "error");
  }
}

async function scanFilePath() {
  const path = document.getElementById("single-file-path-input").value.trim();
  if (!path) {
    showToast("Please enter a file path.", "warning");
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/scan/file`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file_path: path })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to scan file");
    }

    const data = await res.json();
    state.lastFileResult = data;
    renderFileResults(data);
    showToast(`File scanned: ${data.total_findings} issues found`, "success");
  } catch (err) {
    showToast(err.message, "error");
  }
}

async function handleSingleFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch(`${API_BASE}/api/scan/upload`, {
      method: "POST",
      body: formData
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "File upload scan failed");
    }

    const data = await res.json();
    state.lastFileResult = data;
    renderFileResults(data);
    showToast(`Uploaded file scanned: ${data.total_findings} issues found`, "success");
  } catch (err) {
    showToast(err.message, "error");
  }
}

function renderFileResults(data) {
  const container = document.getElementById("file-results-container");
  container.classList.remove("hidden");

  document.getElementById("file-res-filename").innerText = data.filename || "file.py";
  const total = data.total_findings || 0;
  const score = data.score !== undefined ? data.score : 100;
  const stats = data.stats || {};

  document.getElementById("file-res-summary").innerText =
    total === 0 ? "No Security Vulnerabilities Detected" : `Found ${total} Security ${total === 1 ? 'Vulnerability' : 'Vulnerabilities'}`;

  document.getElementById("file-res-stats").innerText =
    `Health Score: ${score}/100 • ${stats.CRITICAL || 0} Critical, ${stats.HIGH || 0} High, ${stats.MEDIUM || 0} Medium, ${stats.LOW || 0} Low`;

  const list = document.getElementById("file-findings-list");
  if (!data.findings || data.findings.length === 0) {
    list.innerHTML = `
      <div class="card-glass p-8 text-center text-slate-500">
        <i data-lucide="shield-check" class="w-10 h-10 text-emerald-400 mx-auto mb-2"></i>
        <h4 class="text-base font-semibold text-slate-200">Clean Code! No security issues found</h4>
        <p class="text-xs mt-1">The AST visitor did not identify any known dangerous patterns or sinks.</p>
      </div>
    `;
    initLucide();
    return;
  }

  list.innerHTML = data.findings.map(f => createFindingCardHTML(f)).join("");
  initLucide();
}

// ─── Finding Card HTML Builder ─────────────────────────────────────────────

function createFindingCardHTML(f) {
  const sev = f.severity || "MEDIUM";
  const sevBadge = `badge-${sev.toLowerCase()}`;
  const borderClass = `finding-card-${sev.toLowerCase()}`;

  let snippetHTML = "";
  if (f.snippet && f.snippet.lines && f.snippet.lines.length > 0) {
    const linesHTML = f.snippet.lines.map(l => {
      const isTarget = l.is_target;
      return `
        <div class="code-line ${isTarget ? 'target' : ''}">
          <span class="line-num">${l.line}</span>
          <span class="code-text">${escapeHTML(l.code)}</span>
        </div>
      `;
    }).join("");

    snippetHTML = `
      <div class="mt-3">
        <div class="text-[11px] font-semibold text-slate-400 mb-1 flex items-center space-x-1.5">
          <i data-lucide="code" class="w-3.5 h-3.5 text-cyan-400"></i>
          <span>Vulnerable Code Context</span>
        </div>
        <div class="code-box">
          ${linesHTML}
        </div>
      </div>
    `;
  }

  return `
    <div class="card-glass p-5 ${borderClass} transition duration-150">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-2.5 py-0.5 rounded-full text-xs font-bold ${sevBadge}">${sev}</span>
          <span class="text-sm font-bold text-white">${escapeHTML(f.category || "Vulnerability")}</span>
          <span class="text-xs font-mono bg-slate-800 text-cyan-400 border border-slate-700 px-2 py-0.5 rounded">${f.cwe || "CWE-Other"}</span>
        </div>
        <div class="text-xs text-slate-400 font-mono flex items-center space-x-1">
          <i data-lucide="map-pin" class="w-3.5 h-3.5 text-slate-500"></i>
          <span>${escapeHTML(f.file || "")} : <strong class="text-cyan-400">L${f.line}</strong></span>
        </div>
      </div>

      <div class="mt-3">
        <p class="text-sm text-slate-200">${escapeHTML(f.message || "")}</p>
      </div>

      ${snippetHTML}

      <div class="mt-3 bg-[#0a101d] border border-cyan-950/70 p-3 rounded-lg flex items-start space-x-2.5">
        <i data-lucide="shield-check" class="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0"></i>
        <div class="text-xs text-slate-300">
          <strong class="text-emerald-400">Remediation Guide:</strong> ${escapeHTML(f.remediation || "Refactor code to follow secure coding standards.")}
        </div>
      </div>
    </div>
  `;
}

function escapeHTML(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ─── TAB 3: AST & MEMORY INSPECTOR ─────────────────────────────────────────

async function loadAstData() {
  const projectPath = document.getElementById("project-path-input").value.trim() || "./project_test";
  try {
    const res = await fetch(`${API_BASE}/api/data_access`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project_path: projectPath, include_ast: true })
    });

    if (!res.ok) throw new Error("Failed to load AST & Memory data");
    const data = await res.json();
    renderAstData(data);
    showToast("AST & Memory analysis completed!", "success");
  } catch (err) {
    showToast(err.message, "error");
  }
}

function renderAstData(data) {
  const memData = data.memory_space_data || {};
  const summary = memData["__summary__"] || {};

  document.getElementById("ast-files-count").innerText = summary.total_py_files_scanned || 0;
  document.getElementById("ast-ram-estimate").innerText = summary.total_estimated_ram_human || "0 MB";

  const accordion = document.getElementById("ast-files-accordion");
  accordion.innerHTML = "";

  for (const [filepath, fileinfo] of Object.entries(memData)) {
    if (filepath.startsWith("__")) continue;

    const sizeKb = (fileinfo.file_size_bytes / 1024).toFixed(1);
    const funcs = fileinfo.functions || [];
    const classes = fileinfo.classes || [];
    const recursive = fileinfo.recursive_functions || [];

    accordion.innerHTML += `
      <div class="border border-slate-800 rounded-lg bg-[#0b111e] p-3 hover:border-slate-700 transition">
        <div class="flex items-center justify-between">
          <div class="font-mono text-xs text-cyan-400 font-semibold truncate max-w-md">
            ${escapeHTML(filepath)}
          </div>
          <div class="text-xs text-slate-400">
            ${sizeKb} KB • Est. RAM: ${(fileinfo.estimated_ram_bytes / 1024).toFixed(0)} KB
          </div>
        </div>
        <div class="mt-2 text-xs text-slate-400 flex flex-wrap gap-2">
          <span class="bg-slate-800 px-2 py-0.5 rounded text-slate-300">Functions: ${funcs.length}</span>
          <span class="bg-slate-800 px-2 py-0.5 rounded text-slate-300">Classes: ${classes.length}</span>
          ${recursive.length > 0 ? `<span class="bg-rose-950 text-rose-400 border border-rose-800 px-2 py-0.5 rounded font-bold">Recursive: ${recursive.join(', ')}</span>` : ''}
        </div>
      </div>
    `;
  }

  initLucide();
}

// ─── TAB 4: AI & KEV THREAT INTELLIGENCE (RAG) ─────────────────────────────

async function runRagCveAnalysis() {
  const projectPath = document.getElementById("project-path-input").value.trim() || "./project_test";
  const loading = document.getElementById("rag-loading");
  const results = document.getElementById("rag-results");

  loading.classList.remove("hidden");
  results.classList.add("hidden");

  try {
    const res = await fetch(`${API_BASE}/api/rag_cve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project_path: projectPath })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "RAG analysis failed");
    }

    const data = await res.json();
    results.classList.remove("hidden");
    document.getElementById("rag-model-badge").innerText = data.model_used || "gemini-2.5-flash";
    document.getElementById("rag-analysis-text").innerText = data.analysis || "No analysis generated.";
    showToast("AI threat report generated!", "success");
  } catch (err) {
    showToast(err.message, "error");
  } finally {
    loading.classList.add("hidden");
  }
}

// ─── TAB 5: RULES CATALOG ──────────────────────────────────────────────────

async function loadRulesCatalog() {
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    if (!res.ok) return;
    const data = await res.json();
    state.rulesList = data.rules || [];
    renderRulesCatalog(state.rulesList);
  } catch (e) {
    console.error("Rules load error:", e);
  }
}

function renderRulesCatalog(rules) {
  const grid = document.getElementById("rules-grid");
  if (!grid) return;

  grid.innerHTML = rules.map(r => `
    <div class="card-glass p-4 border border-slate-800 hover:border-cyan-500/40 transition">
      <div class="flex items-center justify-between mb-2">
        <h4 class="text-sm font-bold text-white">${escapeHTML(r.category)}</h4>
        <span class="text-xs font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-800 px-2 py-0.5 rounded font-semibold">${escapeHTML(r.cwe)}</span>
      </div>
      <p class="text-xs text-slate-300 font-medium">${escapeHTML(r.name)}</p>
      <div class="mt-2.5 pt-2 border-t border-slate-800 text-[11px] text-slate-400">
        <strong class="text-emerald-400">Remediation:</strong> ${escapeHTML(r.remediation)}
      </div>
    </div>
  `).join("");
}

function filterRulesCatalog() {
  const query = document.getElementById("rules-search").value.toLowerCase();
  const filtered = state.rulesList.filter(r =>
    r.category.toLowerCase().includes(query) ||
    r.cwe.toLowerCase().includes(query) ||
    r.name.toLowerCase().includes(query)
  );
  renderRulesCatalog(filtered);
}

// ─── Directory Explorer Modal ──────────────────────────────────────────────

function openDirExplorerModal() {
  const modal = document.getElementById("modal-explorer");
  modal.classList.remove("hidden");
  const path = document.getElementById("project-path-input").value.trim() || ".";
  loadDirExplorer(path);
  initLucide();
}

function closeDirExplorerModal() {
  document.getElementById("modal-explorer").classList.add("hidden");
}

async function loadDirExplorer(path) {
  try {
    const res = await fetch(`${API_BASE}/api/filesystem/browse?path=${encodeURIComponent(path)}`);
    if (!res.ok) throw new Error("Could not browse directory");
    const data = await res.json();

    state.explorerCurrentPath = data.current_path;
    document.getElementById("explorer-current-path").innerText = data.current_path;

    const list = document.getElementById("explorer-list");
    list.innerHTML = "";

    // Favorites / Shortcuts
    if (data.favorites && data.favorites.length > 0) {
      list.innerHTML += `<div class="text-[10px] uppercase font-bold text-slate-500 px-2 pt-1 pb-0.5">Shortcuts</div>`;
      data.favorites.forEach(fav => {
        list.innerHTML += `
          <button onclick="loadDirExplorer('${fav.path.replace(/\\/g, '/')}')" class="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-xs text-cyan-400 flex items-center space-x-2">
            <i data-lucide="star" class="w-3.5 h-3.5 text-cyan-400"></i>
            <span>${fav.label}</span>
          </button>
        `;
      });
      list.innerHTML += `<div class="text-[10px] uppercase font-bold text-slate-500 px-2 pt-2 pb-0.5">Directories</div>`;
    }

    // Subdirectories
    data.directories.forEach(d => {
      const escaped = d.path.replace(/\\/g, '/');
      list.innerHTML += `
        <button onclick="loadDirExplorer('${escaped}')" class="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-xs text-slate-200 flex items-center justify-between group">
          <div class="flex items-center space-x-2 truncate">
            <i data-lucide="folder" class="w-4 h-4 text-cyan-400 flex-shrink-0"></i>
            <span class="truncate">${escapeHTML(d.name)}</span>
          </div>
          ${d.has_python_files ? '<span class="text-[10px] text-cyan-400 bg-cyan-950 px-1.5 py-0.5 rounded border border-cyan-800">contains .py</span>' : ''}
        </button>
      `;
    });

    document.getElementById("explorer-py-count").innerText = `${data.python_files.length} Python files in current folder`;
    initLucide();
  } catch (err) {
    showToast(err.message, "error");
  }
}

function navigateExplorerParent() {
  loadDirExplorer(state.explorerCurrentPath + "/..");
}

function confirmSelectedDirectory() {
  document.getElementById("project-path-input").value = state.explorerCurrentPath;
  closeDirExplorerModal();
  showToast(`Selected directory: ${state.explorerCurrentPath}`, "info");
}

// ─── Settings Modal (Gemini API Key) ───────────────────────────────────────

function openConfigModal() {
  document.getElementById("modal-config").classList.remove("hidden");
  initLucide();
}

function closeConfigModal() {
  document.getElementById("modal-config").classList.add("hidden");
}

async function saveGeminiKey() {
  const key = document.getElementById("cfg-gemini-key").value.trim();
  if (!key) {
    showToast("Please enter an API key.", "warning");
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/config/gemini`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_key: key })
    });

    if (!res.ok) throw new Error("Failed to save key");
    showToast("Gemini API key saved successfully!", "success");
    closeConfigModal();
  } catch (err) {
    showToast(err.message, "error");
  }
}

// ─── Export Report ─────────────────────────────────────────────────────────

function exportReportJSON() {
  if (!state.lastProjectResult) {
    showToast("No scan results to export.", "warning");
    return;
  }
  const blob = new Blob([JSON.stringify(state.lastProjectResult, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sast-report-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast("Report exported as JSON", "success");
}

// ─── Toast Notifications ───────────────────────────────────────────────────

function showToast(message, type = "info") {
  const toast = document.getElementById("toast");
  const msgEl = document.getElementById("toast-message");
  const icon = document.getElementById("toast-icon");

  msgEl.innerText = message;
  toast.className = "fixed bottom-5 right-5 z-50 transition-all duration-300 px-4 py-3 rounded-xl shadow-2xl flex items-center space-x-2.5 text-sm font-medium border " +
    (type === "error" ? "bg-rose-950 border-rose-800 text-rose-200" :
     type === "success" ? "bg-emerald-950 border-emerald-800 text-emerald-200" :
     type === "warning" ? "bg-amber-950 border-amber-800 text-amber-200" :
     "bg-slate-900 border-slate-700 text-slate-100");

  toast.classList.remove("translate-y-20", "opacity-0");
  setTimeout(() => {
    toast.classList.add("translate-y-20", "opacity-0");
  }, 4000);
}
