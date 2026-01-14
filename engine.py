import ast
import os
import hashlib
import importlib.util
from collections import defaultdict

class PowerScanner(ast.NodeVisitor):
    def __init__(self, filename="<unknown>"):
        self.filename = filename
        self.findings = []
        self.imported_modules = []  # For graph theory: collecting potential local imports
        self.aliases = defaultdict(set)  # For set theory: simple alias analysis
        self.sensitive_vars = set()  # Track sensitive variables
        # Configuration for what we consider dangerous
        self.dangerous_sinks = {
            'eval', 'exec', 'compile', 'input',
            'os.system', 'os.popen', 'os.execv', 'os.execl', 'os.spawnv',
            'subprocess.call', 'subprocess.check_call', 'subprocess.check_output', 'subprocess.run'
        }
        self.sensitive_keywords = {
            'api_key', 'password', 'secret', 'token', 'credentials',
            'key', 'pwd', 'auth', 'access_token', 'session_id'
        }
        self.unsafe_modules = {
            'pickle', 'cPickle', 'dill', 'marshal', 'shelve',
            'yaml', 'xml.etree.ElementTree', 'imp', 'cgi', 'ftplib', 'telnetlib'
        }
        self.weak_hashes = {'md5', 'sha1'}
        self.severities = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    def report(self, node, severity, category, message):
        """Standardized reporting format."""
        if severity not in self.severities:
            severity = 'MEDIUM'  # Default fallback
        self.findings.append({
            "file": self.filename,
            "line": node.lineno,
            "col": node.col_offset,
            "severity": severity,
            "category": category,
            "message": message
        })

    def visit_Import(self, node):
        """Check for unsafe import statements and collect potential local imports."""
        for alias in node.names:
            base_name = alias.name.split('.')[0]  # Handle submodules
            if base_name in self.unsafe_modules:
                self.report(node, "MEDIUM", "Insecure Import", f"Unsafe module '{alias.name}' can lead to vulnerabilities like RCE or data exposure.")
            # Collect for graph
            if '.' not in alias.name:
                self.imported_modules.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """Check for unsafe from-import statements and collect potential local imports."""
        if node.module:
            base_module = node.module.split('.')[0]
            if base_module in self.unsafe_modules:
                self.report(node, "MEDIUM", "Insecure Import", f"Unsafe module '{node.module}' imported.")
            # Collect for graph if relative level == 0
            if node.level == 0 and node.module:
                self.imported_modules.append(node.module.split('.')[0])
        self.generic_visit(node)

    def get_all_aliases(self, var):
        """Recursive function to get all aliases using set theory."""
        all_aliases = {var}
        for alias in self.aliases[var]:
            all_aliases.update(self.get_all_aliases(alias))
        return all_aliases

    def visit_Call(self, node):
        """Check for Dangerous Function Calls (Sinks) and specific insecure usages, including sensitive data exposure via aliases."""
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

                # Check for weak hashing algorithms
                if node.func.value.id == 'hashlib' and node.func.attr in self.weak_hashes:
                    self.report(node, "MEDIUM", "Weak Cryptography", f"Use of weak hash '{node.func.attr}' – consider stronger alternatives like sha256.")

            # Special handling for subprocess with shell=True
            if isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
                if node.func.attr in {'Popen', 'call', 'check_call', 'check_output', 'run'}:
                    shell_true = False
                    for kw in node.keywords:
                        if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            shell_true = True
                            break
                    if shell_true:
                        self.report(node, "CRITICAL", "Command Injection", f"subprocess.{node.func.attr} with shell=True enables shell injection.")

            # Insecure deserialization calls, e.g., pickle.load, yaml.load without safe loader
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                func = node.func.attr
                if module == 'pickle' and func in {'load', 'loads'}:
                    self.report(node, "HIGH", "Insecure Deserialization", f"'{module}.{func}' can lead to RCE if data is untrusted.")
                elif module == 'yaml' and func == 'load':
                    safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == 'Loader' and isinstance(kw.value, ast.Attribute) and kw.value.attr == 'SafeLoader':
                            safe_loader = True
                            break
                    if not safe_loader:
                        self.report(node, "HIGH", "Insecure Deserialization", f"'{module}.{func}' without SafeLoader can be unsafe.")
                elif module == 'xml' and func in {'fromstring', 'parse'}:
                    self.report(node, "MEDIUM", "XML Vulnerability", f"Potential XXE in '{module}.{func}' – use defusedxml instead.")

        # Check for sensitive data exposure in arguments via aliases
        for arg in node.args:
            if isinstance(arg, ast.Name):
                all_aliases = self.get_all_aliases(arg.id)
                if self.sensitive_vars & all_aliases:
                    self.report(node, "MEDIUM", "Sensitive Data Exposure", f"Sensitive variable '{arg.id}' (or alias) used in call to {func_name or full_name}.")

        self.generic_visit(node)

    def visit_Assign(self, node):
        """Check for Hardcoded Secrets and track aliases using set theory."""
        is_sensitive = False
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(key in var_name for key in self.sensitive_keywords):
                    if isinstance(node.value, (ast.Constant, ast.Str, ast.Bytes)):  # Handles strings, bytes
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

    def visit_ExceptHandler(self, node):
        """Check for bare except: statements."""
        if node.type is None:
            self.report(node, "LOW", "Poor Error Handling", "Bare 'except:' can hide important errors – specify exception types.")
        self.generic_visit(node)

    def visit_Assert(self, node):
        """Check for assert statements, which are disabled in optimized mode."""
        self.report(node, "LOW", "Debug Statement", "Assert statements are for debugging and disabled in production (-O flag).")
        self.generic_visit(node)

    def visit_BinOp(self, node):
        """Basic check for potential SQL injection via string concatenation."""
        if isinstance(node.op, ast.Add) and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            if any(sql_kw in node.left.value.upper() for sql_kw in {'SELECT', 'INSERT', 'UPDATE', 'DELETE'}):
                if not isinstance(node.right, ast.Constant):  # If right is variable or expression
                    self.report(node, "MEDIUM", "Potential SQL Injection", "String concatenation in potential SQL query – use parameterized queries.")
        self.generic_visit(node)

    def visit_Attribute(self, node):
        """Check for access to sensitive attributes, e.g., os.environ['API_KEY']."""
        if isinstance(node.value, ast.Name) and node.value.id == 'os' and node.attr == 'environ':
            self.report(node, "LOW", "Sensitive Access", "Access to os.environ may expose sensitive environment variables.")
        self.generic_visit(node)

def run_scanner(file_path):
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return [], []

    with open(file_path, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source)
        scanner = PowerScanner(file_path)
        scanner.visit(tree)
        return scanner.findings, scanner.imported_modules
    except SyntaxError as e:
        print(f"Failed to parse {file_path}: {e}")
        return [], []

def has_cycle(graph):
    """DFS to detect cycles in the import graph (Graph Theory)."""
    visited = set()
    rec_stack = set()

    def dfs(node):
        visited.add(node)
        rec_stack.add(node)
        for neighbor in graph[node]:
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

def scan_directory(directory_path):
    """Walks through a directory and scans all .py files, includes SCA and import graph analysis."""
    all_findings = []
    all_scanners = []
    py_files = []
    vulnerable_deps = {
        'urllib3': {'vulnerable_versions': ['<2.6.0'], 'cve': 'CVE-2025-66418', 'description': 'Unbounded decompression chain leading to high CPU and memory usage.'},
        'python-json-logger': {'vulnerable_versions': ['3.2.0', '3.2.1'], 'cve': 'CVE-2025-27607', 'description': 'RCE due to dependency hijacking.'},
        'python-socketio': {'vulnerable_versions': ['<5.14.0'], 'cve': 'CVE-2025-61765', 'description': 'RCE via pickle deserialization.'},
        'aiohttp': {'vulnerable_versions': ['<3.13.3'], 'cve': 'CVE-2025-69224', 'description': 'Request smuggling with non-ASCII characters.'},
    }

    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                py_files.append(full_path)
                print(f"--- Scanning: {full_path} ---")
                
                findings, imported_modules = run_scanner(full_path)
                all_findings.extend(findings)
                scanner = PowerScanner(full_path)  # Re-instantiate for info
                scanner.imported_modules = imported_modules
                all_scanners.append(scanner)

    # Build module to file map (assuming flat structure, no subpackages)
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
            "severity": "MEDIUM",
            "category": "Circular Import",
            "message": "Cycle detected in import graph, which may cause runtime issues."
        })

    # SCA: Inventory and hashing
    req_path = os.path.join(directory_path, 'requirements.txt')
    if os.path.exists(req_path):
        with open(req_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        dependencies = {}
        import re
        for line in lines:
            # Simple regex to grab the package name (START of string until we hit a non-pkg char)
            # Standard python packaging names: letters, numbers, _, -, .
            match = re.match(r'^([a-zA-Z0-9_\-\.]+)', line)
            if match:
                pkg_name = match.group(1)
                # Try to extract version if == is present, else None
                ver = None
                if '==' in line:
                    parts = line.split('==')
                    if len(parts) > 1:
                        ver = parts[1].strip()
                dependencies[pkg_name] = ver

        for pkg, ver in dependencies.items():
            # Check for vulnerabilities
            if pkg in vulnerable_deps:
                vuln_info = vulnerable_deps[pkg]
                vulnerable = False
                if ver is None:
                    vulnerable = True
                else:
                    for vrange in vuln_info['vulnerable_versions']:
                        if vrange.startswith('<'):
                            # Simple string compare, assume versions are comparable
                            if ver < vrange[1:]:
                                vulnerable = True
                        elif vrange.startswith('>'):
                            if ver > vrange[1:]:
                                vulnerable = True
                        elif ver == vrange:
                            vulnerable = True
                if vulnerable:
                    all_findings.append({
                        "file": req_path,
                        "line": 0,
                        "col": 0,
                        "severity": "HIGH",
                        "category": "Vulnerable Dependency",
                        "message": f"Vulnerable dependency {pkg} {ver or 'unspecified'}: {vuln_info['description']} ({vuln_info['cve']})"
                    })

            # Hashing if package is installed
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
                        "severity": "INFO",
                        "category": "Dependency Hash",
                        "message": f"SHA256 hash for {pkg} (__file__): {hash_val}"
                    })
                except Exception as e:
                    pass  # Skip if can't read

    return all_findings

if __name__ == "__main__":
    project_to_scan = "./project_test"  # Change this to your folder
    
    if not os.path.isdir(project_to_scan):
        print("Please provide a valid directory path.")
    else:
        results = scan_directory(project_to_scan)
        
        print("\n" + "="*50)
        print(f"SCAN COMPLETE: Found {len(results)} issues")
        print("="*50 + "\n")
        
        for issue in results:
            print(f"[{issue['severity']}] {issue['category']}")
            print(f"File: {issue['file']} | Line: {issue['line']}")
            print(f"Message: {issue['message']}")
            print("-" * 30)