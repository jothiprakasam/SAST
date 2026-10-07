import ast
import os
import hashlib
import importlib.util
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional

try:
    from packaging.version import parse as parse_version
except ImportError:
    parse_version = None

CWE_METADATA = {
    "Dangerous Sink": {
        "cwe": "CWE-95",
        "name": "Improper Neutralization of Directives in Dynamically Evaluated Code",
        "remediation": "Avoid executing dynamic code strings with eval/exec/compile. Use ast.literal_eval or structured data parsers like json."
    },
    "Command Injection": {
        "cwe": "CWE-78",
        "name": "Improper Neutralization of Special Elements used in an OS Command",
        "remediation": "Do not pass shell=True or concatenate user input into shell commands. Pass argument lists to subprocess without shell=True."
    },
    "Hardcoded Secret": {
        "cwe": "CWE-798",
        "name": "Use of Hard-coded Credentials",
        "remediation": "Store secrets, passwords, and API keys in environment variables or a secure vault (e.g., .env, AWS Secrets Manager, HashiCorp Vault)."
    },
    "Weak Cryptography": {
        "cwe": "CWE-327",
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "remediation": "Replace MD5/SHA1 with secure hashing algorithms like SHA-256 or SHA-3, and use bcrypt/Argon2 for passwords."
    },
    "Insecure Deserialization": {
        "cwe": "CWE-502",
        "name": "Deserialization of Untrusted Data",
        "remediation": "Never deserialize untrusted data with pickle or unsafe yaml loaders. Use json or yaml.safe_load instead."
    },
    "Insecure Import": {
        "cwe": "CWE-676",
        "name": "Use of Potentially Dangerous Function or Module",
        "remediation": "Replace deprecated or dangerous modules (e.g., telnetlib, cPickle, imp) with secure and actively maintained libraries."
    },
    "Potential SQL Injection": {
        "cwe": "CWE-89",
        "name": "Improper Neutralization of Special Elements used in an SQL Command",
        "remediation": "Use parameterized queries or ORM query builders (e.g. Django ORM, SQLAlchemy). Never interpolate or concatenate variables directly into SQL."
    },
    "Sensitive Data Exposure": {
        "cwe": "CWE-200",
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "remediation": "Sanitize and mask sensitive variables before passing to loggers, APIs, or unencrypted storage."
    },
    "Poor Error Handling": {
        "cwe": "CWE-391",
        "name": "Unchecked Error Condition",
        "remediation": "Specify explicit exception classes instead of bare 'except:'. Bare except clauses catch SystemExit, KeyboardInterrupt, and mask security flaws."
    },
    "Debug Statement": {
        "cwe": "CWE-489",
        "name": "Active Debug Code",
        "remediation": "Do not rely on 'assert' statements for application security or business logic; Python disables asserts under -O (optimized) mode."
    },
    "Sensitive Access": {
        "cwe": "CWE-200",
        "name": "Information Exposure Through Environment Access",
        "remediation": "Carefully manage os.environ access. Validate and sanitize keys to avoid logging or exposing sensitive environment variables."
    },
    "Insecure Temp File": {
        "cwe": "CWE-377",
        "name": "Insecure Temporary File",
        "remediation": "Avoid tempfile.mktemp() which is vulnerable to race conditions (TOCTOU). Use tempfile.NamedTemporaryFile() instead."
    },
    "Insecure Debug Configuration": {
        "cwe": "CWE-489",
        "name": "Active Debug Code in Configuration",
        "remediation": "Set DEBUG = False in production configurations to prevent disclosing sensitive stack traces and settings."
    },
    "XML Vulnerability": {
        "cwe": "CWE-611",
        "name": "Improper Restriction of XML External Entity Reference (XXE)",
        "remediation": "Use defusedxml instead of standard xml.etree / xml.sax to prevent XXE, XML entity expansion, and DoS attacks."
    },
    "Circular Import": {
        "cwe": "CWE-400",
        "name": "Uncontrolled Resource Consumption (Import Cycle)",
        "remediation": "Refactor module structure to break circular dependencies or move imports into function bodies."
    },
    "Vulnerable Dependency": {
        "cwe": "CWE-1395",
        "name": "Dependency on Vulnerable Third-Party Component",
        "remediation": "Upgrade the vulnerable library in requirements.txt to the recommended patched version."
    },
    "Dependency Hash": {
        "cwe": "CWE-353",
        "name": "Integrity Verification",
        "remediation": "Record and enforce cryptographic hashes (pip hash-checking mode) to prevent supply chain tampering."
    }
}


class PowerScanner(ast.NodeVisitor):
    def __init__(self, filename: str = "<unknown>", source_code: Optional[str] = None):
        self.filename = filename
        self.findings = []
        self.imported_modules = []  # For graph theory
        self.aliases = defaultdict(set)  # For set theory alias analysis
        self.sensitive_vars = set()  # Track sensitive variables
        self.source_code = source_code
        self.source_lines = source_code.splitlines() if source_code is not None else []

        # Dangerous sinks
        self.dangerous_sinks = {
            'eval', 'exec', 'compile', 'input',
            'os.system', 'os.popen', 'os.execv', 'os.execl', 'os.spawnv',
            'subprocess.call', 'subprocess.check_call', 'subprocess.check_output', 'subprocess.run'
        }
        self.sensitive_keywords = {
            'api_key', 'password', 'secret', 'token', 'credentials',
            'key', 'pwd', 'auth', 'access_token', 'session_id', 'private_key'
        }
        self.unsafe_modules = {
            'pickle', 'cPickle', 'dill', 'marshal', 'shelve',
            'yaml', 'xml.etree.ElementTree', 'imp', 'cgi', 'ftplib', 'telnetlib'
        }
        self.weak_hashes = {'md5', 'sha1'}
        self.severities = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    def _get_snippet(self, lineno: int) -> Dict[str, Any]:
        """Extract surrounding code context lines for visual display."""
        if not self.source_lines or lineno < 1 or lineno > len(self.source_lines):
            return {"start_line": lineno, "end_line": lineno, "lines": []}
        
        start = max(1, lineno - 2)
        end = min(len(self.source_lines), lineno + 2)
        lines = []
        for ln in range(start, end + 1):
            lines.append({
                "line": ln,
                "code": self.source_lines[ln - 1],
                "is_target": (ln == lineno)
            })
        return {
            "start_line": start,
            "end_line": end,
            "target_line": lineno,
            "lines": lines
        }

    def report(self, node: ast.AST, severity: str, category: str, message: str, cwe: Optional[str] = None):
        """Standardized reporting format with CWE, remediation, and snippet."""
        if severity not in self.severities:
            severity = 'MEDIUM'
        
        meta = CWE_METADATA.get(category, {})
        cwe_id = cwe or meta.get("cwe", "CWE-Other")
        remediation = meta.get("remediation", "Review and refactor code according to secure coding practices.")

        lineno = getattr(node, "lineno", 0)
        col_offset = getattr(node, "col_offset", 0)
        end_lineno = getattr(node, "end_lineno", lineno)
        end_col_offset = getattr(node, "end_col_offset", col_offset)

        snippet = self._get_snippet(lineno)

        self.findings.append({
            "file": self.filename,
            "line": lineno,
            "col": col_offset,
            "end_line": end_lineno,
            "end_col": end_col_offset,
            "severity": severity,
            "category": category,
            "message": message,
            "cwe": cwe_id,
            "cwe_name": meta.get("name", category),
            "remediation": remediation,
            "snippet": snippet
        })

    def visit_Import(self, node: ast.Import):
        """Check for unsafe import statements and collect potential local imports."""
        for alias in node.names:
            base_name = alias.name.split('.')[0]
            if base_name in self.unsafe_modules:
                self.report(
                    node, "MEDIUM", "Insecure Import",
                    f"Unsafe module '{alias.name}' can lead to vulnerabilities like RCE or data exposure."
                )
            if '.' not in alias.name:
                self.imported_modules.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Check for unsafe from-import statements and collect potential local imports."""
        if node.module:
            base_module = node.module.split('.')[0]
            if base_module in self.unsafe_modules:
                self.report(
                    node, "MEDIUM", "Insecure Import",
                    f"Unsafe module '{node.module}' imported."
                )
            if node.level == 0 and node.module:
                self.imported_modules.append(node.module.split('.')[0])
        self.generic_visit(node)

    def get_all_aliases(self, var: str) -> set:
        """Recursive function to get all aliases using set theory."""
        all_aliases = {var}
        for alias in self.aliases[var]:
            all_aliases.update(self.get_all_aliases(alias))
        return all_aliases

    def visit_Call(self, node: ast.Call):
        """Check for Dangerous Function Calls (Sinks) and insecure usages."""
        func_name = None
        full_name = None

        # Direct calls like eval()
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.dangerous_sinks:
                self.report(node, "HIGH", "Dangerous Sink", f"Execution of interpreted code via '{func_name}'.")

        # Attribute calls like os.system() or hashlib.md5()
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                full_name = f"{node.func.value.id}.{node.func.attr}"
                if full_name in self.dangerous_sinks:
                    self.report(node, "HIGH", "Command Injection", f"Potential shell injection via '{full_name}'.")

                if node.func.value.id == 'hashlib' and node.func.attr in self.weak_hashes:
                    self.report(
                        node, "MEDIUM", "Weak Cryptography",
                        f"Use of weak hash '{node.func.attr}' – consider stronger alternatives like sha256."
                    )

            # Special handling for subprocess with shell=True
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
                if node.func.attr in {'Popen', 'call', 'check_call', 'check_output', 'run'}:
                    shell_true = False
                    for kw in node.keywords:
                        if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            shell_true = True
                            break
                    if shell_true:
                        self.report(
                            node, "CRITICAL", "Command Injection",
                            f"subprocess.{node.func.attr} with shell=True enables shell injection."
                        )

            # Insecure tempfile.mktemp
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'tempfile' and node.func.attr == 'mktemp':
                self.report(
                    node, "HIGH", "Insecure Temp File",
                    "tempfile.mktemp() is vulnerable to race conditions. Use tempfile.NamedTemporaryFile() instead."
                )

            # Insecure deserialization calls
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                func = node.func.attr
                if module == 'pickle' and func in {'load', 'loads'}:
                    self.report(node, "HIGH", "Insecure Deserialization", f"'{module}.{func}' can lead to RCE if data is untrusted.")
                elif module == 'yaml' and func in {'load', 'unsafe_load'}:
                    safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == 'Loader' and isinstance(kw.value, ast.Attribute) and kw.value.attr == 'SafeLoader':
                            safe_loader = True
                            break
                    if not safe_loader or func == 'unsafe_load':
                        self.report(node, "HIGH", "Insecure Deserialization", f"'{module}.{func}' without SafeLoader can be unsafe.")
                elif module in {'xml', 'ElementTree'} and func in {'fromstring', 'parse'}:
                    self.report(node, "MEDIUM", "XML Vulnerability", f"Potential XXE in '{module}.{func}' – use defusedxml instead.")

        # Check for sensitive data exposure in arguments via aliases
        for arg in node.args:
            if isinstance(arg, ast.Name):
                all_aliases = self.get_all_aliases(arg.id)
                if self.sensitive_vars & all_aliases:
                    self.report(
                        node, "MEDIUM", "Sensitive Data Exposure",
                        f"Sensitive variable '{arg.id}' (or alias) used in call to {func_name or full_name}."
                    )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Check for Hardcoded Secrets, Insecure DEBUG=True, and track aliases."""
        is_sensitive = False
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                
                # Check for DEBUG = True (CWE-489)
                if target.id == 'DEBUG' and isinstance(node.value, ast.Constant) and node.value.value is True:
                    self.report(
                        node, "MEDIUM", "Insecure Debug Configuration",
                        "DEBUG is set to True. Ensure debug mode is disabled in production."
                    )

                # Check for sensitive keywords
                if any(key in var_name for key in self.sensitive_keywords):
                    # Python 3.8+ compatibility: use ast.Constant
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes)):
                        # If value is non-empty and not just an env var placeholder
                        val_str = str(node.value.value)
                        if len(val_str) > 0 and not val_str.startswith("$") and not val_str.startswith("{"):
                            self.report(node, "HIGH", "Hardcoded Secret", f"Potential sensitive data in variable '{target.id}'.")
                            is_sensitive = True

                # Alias tracking
                if isinstance(node.value, ast.Name):
                    self.aliases[target.id].add(node.value.id)

        if is_sensitive:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.sensitive_vars.add(target.id)

        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        """Check for bare except: statements."""
        if node.type is None:
            self.report(node, "LOW", "Poor Error Handling", "Bare 'except:' can hide important errors – specify exception types.")
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        """Check for assert statements, which are disabled in optimized mode."""
        self.report(node, "LOW", "Debug Statement", "Assert statements are for debugging and disabled in production (-O flag).")
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        """Basic check for potential SQL injection via string concatenation."""
        sql_keywords = {'SELECT ', 'INSERT INTO ', 'UPDATE ', 'DELETE FROM '}
        if isinstance(node.op, ast.Add) and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            if any(sql_kw in node.left.value.upper() for sql_kw in sql_keywords):
                if not isinstance(node.right, ast.Constant):
                    self.report(
                        node, "HIGH", "Potential SQL Injection",
                        "String concatenation in potential SQL query – use parameterized queries."
                    )
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        """Check for SQL injection via f-strings."""
        sql_keywords = {'SELECT ', 'INSERT INTO ', 'UPDATE ', 'DELETE FROM '}
        has_sql = False
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                if any(sql_kw in part.value.upper() for sql_kw in sql_keywords):
                    has_sql = True
                    break
        if has_sql and len(node.values) > 1:
            self.report(
                node, "HIGH", "Potential SQL Injection",
                "Direct f-string formatting in SQL query enables SQL injection. Use parameterized queries."
            )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        """Check for access to sensitive attributes, e.g., os.environ."""
        if isinstance(node.value, ast.Name) and node.value.id == 'os' and node.attr == 'environ':
            self.report(node, "LOW", "Sensitive Access", "Access to os.environ may expose sensitive environment variables.")
        self.generic_visit(node)


def calculate_security_score(findings: List[dict]) -> int:
    """Calculates a 0-100 security health score based on findings count and severities."""
    deductions = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 1
    }
    score = 100
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        score -= deductions.get(sev, 5)
    return max(0, score)


def summarize_findings_counts(findings: List[dict]) -> Dict[str, int]:
    """Generates counts for each severity."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": len(findings)}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        if sev in counts:
            counts[sev] += 1
    return counts


def scan_code(source_code: str, filename: str = "<snippet>") -> Dict[str, Any]:
    """Scans raw Python source code string and returns structured findings and stats."""
    if not source_code.strip():
        return {
            "filename": filename,
            "total_findings": 0,
            "findings": [],
            "stats": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": 0},
            "score": 100,
            "imported_modules": []
        }

    try:
        tree = ast.parse(source_code)
        scanner = PowerScanner(filename=filename, source_code=source_code)
        scanner.visit(tree)
        findings = scanner.findings
        imported = scanner.imported_modules
    except SyntaxError as e:
        findings = [{
            "file": filename,
            "line": e.lineno or 1,
            "col": e.offset or 0,
            "end_line": e.lineno or 1,
            "end_col": e.offset or 0,
            "severity": "CRITICAL",
            "category": "Syntax Error",
            "message": f"Syntax Error: {e.msg}",
            "cwe": "CWE-Other",
            "cwe_name": "Syntax Error",
            "remediation": "Correct the syntax error so code can be compiled and analyzed.",
            "snippet": {
                "start_line": max(1, (e.lineno or 1) - 1),
                "end_line": (e.lineno or 1) + 1,
                "target_line": e.lineno or 1,
                "lines": [{"line": e.lineno or 1, "code": e.text.strip() if e.text else "", "is_target": True}]
            }
        }]
        imported = []

    return {
        "filename": filename,
        "total_findings": len(findings),
        "findings": findings,
        "stats": summarize_findings_counts(findings),
        "score": calculate_security_score(findings),
        "imported_modules": imported
    }


def scan_file(file_path: str) -> Dict[str, Any]:
    """Scans a single Python file on disk and returns structured findings and stats."""
    if not os.path.exists(file_path):
        return {
            "error": f"File not found: {file_path}",
            "filename": file_path,
            "total_findings": 0,
            "findings": [],
            "stats": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": 0},
            "score": 100
        }

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
    except Exception as e:
        return {
            "error": f"Failed to read file: {e}",
            "filename": file_path,
            "total_findings": 0,
            "findings": [],
            "stats": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "TOTAL": 0},
            "score": 100
        }

    result = scan_code(source, filename=file_path)
    result["file_size_bytes"] = len(source.encode('utf-8'))
    result["line_count"] = len(source.splitlines())
    return result


def run_scanner(file_path: str) -> Tuple[List[dict], List[str]]:
    """Legacy helper maintained for backward compatibility."""
    res = scan_file(file_path)
    return res.get("findings", []), res.get("imported_modules", [])


def has_cycle(graph: Dict[str, List[str]]) -> bool:
    """DFS to detect cycles in the import graph (Graph Theory)."""
    visited = set()
    rec_stack = set()

    def dfs(node):
        visited.add(node)
        rec_stack.add(node)
        for neighbor in graph.get(node, []):
            if neighbor not in visited:
                if dfs(neighbor):
                    return True
            elif neighbor in rec_stack:
                return True
        rec_stack.remove(node)
        return False

    for node in list(graph.keys()):
        if node not in visited:
            if dfs(node):
                return True
    return False


def _check_version_vulnerable(installed_ver: Optional[str], vrange: str) -> bool:
    """Accurate version checking using packaging.version when available."""
    if installed_ver is None:
        return True
    
    if parse_version:
        try:
            inst = parse_version(installed_ver)
            if vrange.startswith('<='):
                target = parse_version(vrange[2:])
                return inst <= target
            elif vrange.startswith('<'):
                target = parse_version(vrange[1:])
                return inst < target
            elif vrange.startswith('>='):
                target = parse_version(vrange[2:])
                return inst >= target
            elif vrange.startswith('>'):
                target = parse_version(vrange[1:])
                return inst > target
            else:
                return inst == parse_version(vrange)
        except Exception:
            pass

    # Basic fallback
    if vrange.startswith('<='):
        return installed_ver <= vrange[2:]
    elif vrange.startswith('<'):
        return installed_ver < vrange[1:]
    elif vrange.startswith('>='):
        return installed_ver >= vrange[2:]
    elif vrange.startswith('>'):
        return installed_ver > vrange[1:]
    return installed_ver == vrange


def scan_directory(directory_path: str) -> List[dict]:
    """Walks through a directory and scans all .py files, includes SCA and import graph analysis."""
    all_findings = []
    all_scanners = []
    py_files = []

    vulnerable_deps = {
        'urllib3': {
            'vulnerable_versions': ['<2.6.0'],
            'cve': 'CVE-2025-66418',
            'description': 'Unbounded decompression chain leading to high CPU and memory usage.'
        },
        'python-json-logger': {
            'vulnerable_versions': ['3.2.0', '3.2.1'],
            'cve': 'CVE-2025-27607',
            'description': 'RCE due to dependency hijacking.'
        },
        'python-socketio': {
            'vulnerable_versions': ['<5.14.0'],
            'cve': 'CVE-2025-61765',
            'description': 'RCE via pickle deserialization.'
        },
        'aiohttp': {
            'vulnerable_versions': ['<3.13.3'],
            'cve': 'CVE-2025-69224',
            'description': 'Request smuggling with non-ASCII characters.'
        },
        'jinja2': {
            'vulnerable_versions': ['<3.1.5'],
            'cve': 'CVE-2024-56326',
            'description': 'Sandbox breakout and template injection vulnerability.'
        },
        'requests': {
            'vulnerable_versions': ['<2.31.0'],
            'cve': 'CVE-2023-32681',
            'description': 'Unintended leak of Proxy-Authorization header.'
        }
    }

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                py_files.append(full_path)
                
                res = scan_file(full_path)
                findings = res.get("findings", [])
                all_findings.extend(findings)

                scanner = PowerScanner(full_path)
                scanner.imported_modules = res.get("imported_modules", [])
                all_scanners.append(scanner)

    # Build module to file map
    modules_to_files = {}
    for full_path in py_files:
        module_name = os.path.basename(full_path)[:-3]
        if module_name != '__init__':
            modules_to_files[module_name] = full_path

    # Build import graph
    graph = defaultdict(list)
    for scanner in all_scanners:
        module_name = os.path.basename(scanner.filename)[:-3]
        for imp in scanner.imported_modules:
            if imp in modules_to_files:
                graph[module_name].append(imp)

    # Detect cycles using DFS
    if has_cycle(graph):
        all_findings.append({
            "file": directory_path,
            "line": 0,
            "col": 0,
            "end_line": 0,
            "end_col": 0,
            "severity": "MEDIUM",
            "category": "Circular Import",
            "message": "Cycle detected in import graph, which may cause runtime import errors.",
            "cwe": "CWE-400",
            "cwe_name": "Circular Dependency Cycle",
            "remediation": "Refactor interdependent modules into a shared base or use local imports inside functions.",
            "snippet": {"start_line": 0, "end_line": 0, "lines": []}
        })

    # SCA: Inventory and hashing from requirements.txt
    req_path = os.path.join(directory_path, 'requirements.txt')
    if os.path.exists(req_path):
        with open(req_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        dependencies = {}
        for line in lines:
            if '==' in line:
                parts = line.split('==')
                dependencies[parts[0].strip()] = parts[1].strip()
            elif '>=' in line:
                parts = line.split('>=')
                dependencies[parts[0].strip()] = parts[1].strip()
            elif '<=' in line:
                parts = line.split('<=')
                dependencies[parts[0].strip()] = parts[1].strip()
            else:
                dependencies[line.strip()] = None

        for pkg, ver in dependencies.items():
            if pkg in vulnerable_deps:
                vuln_info = vulnerable_deps[pkg]
                is_vuln = False
                for vrange in vuln_info['vulnerable_versions']:
                    if _check_version_vulnerable(ver, vrange):
                        is_vuln = True
                        break

                if is_vuln:
                    all_findings.append({
                        "file": req_path,
                        "line": 0,
                        "col": 0,
                        "end_line": 0,
                        "end_col": 0,
                        "severity": "HIGH",
                        "category": "Vulnerable Dependency",
                        "message": f"Vulnerable dependency {pkg} {ver or 'unspecified'}: {vuln_info['description']} ({vuln_info['cve']})",
                        "cwe": "CWE-1395",
                        "cwe_name": "Vulnerable Third-Party Component",
                        "remediation": f"Upgrade {pkg} to a secure version in requirements.txt.",
                        "snippet": {"start_line": 0, "end_line": 0, "lines": []}
                    })

            # Check installed hash
            spec = importlib.util.find_spec(pkg)
            if spec and spec.origin:
                try:
                    with open(spec.origin, 'rb') as f:
                        content = f.read()
                        hash_val = hashlib.sha256(content).hexdigest()
                    all_findings.append({
                        "file": req_path,
                        "line": 0,
                        "col": 0,
                        "end_line": 0,
                        "end_col": 0,
                        "severity": "INFO",
                        "category": "Dependency Hash",
                        "message": f"SHA256 hash for {pkg} ({spec.origin}): {hash_val}",
                        "cwe": "CWE-353",
                        "cwe_name": "Dependency Verification",
                        "remediation": "Record hash in requirements.txt --require-hashes for supply chain verification.",
                        "snippet": {"start_line": 0, "end_line": 0, "lines": []}
                    })
                except Exception:
                    pass

    return all_findings


if __name__ == "__main__":
    project_to_scan = "./project_test"
    if not os.path.isdir(project_to_scan):
        print(f"Please provide a valid directory path: {project_to_scan}")
    else:
        results = scan_directory(project_to_scan)
        print("\n" + "=" * 50)
        print(f"SCAN COMPLETE: Found {len(results)} issues")
        print("=" * 50 + "\n")
        for issue in results:
            print(f"[{issue['severity']}] {issue['category']} ({issue.get('cwe', '')})")
            print(f"File: {issue['file']} | Line: {issue['line']}")
            print(f"Message: {issue['message']}")
            print("-" * 30)