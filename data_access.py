import ast
import os
import json
from collections import defaultdict

def ast_to_dict(node):
    """Recursive conversion of AST node to dictionary for serialization."""
    if not isinstance(node, ast.AST):
        if isinstance(node, (int, float, str, bool, type(None))):
            return node
        else:
            return str(node)
    d = {"type": node.__class__.__name__}
    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            d[field] = [ast_to_dict(v) for v in value]
        elif isinstance(value, ast.AST):
            d[field] = ast_to_dict(value)
        else:
            d[field] = ast_to_dict(value)
    return d

def ast_view(directory_path):
    """Provides AST view data for the whole project, accessible for frontend/dashboard."""
    all_ast = {}
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        source = f.read()
                    tree = ast.parse(source)
                    all_ast[full_path] = ast_to_dict(tree)
                except Exception as e:
                    all_ast[full_path] = {"error": str(e)}
    
    return all_ast

class CallGraphVisitor(ast.NodeVisitor):
    """Visitor to build call graph for detecting recursion."""
    def __init__(self):
        self.functions = set()
        self.calls = defaultdict(list)
        self.current_func = None

    def visit_FunctionDef(self, node):
        self.current_func = node.name
        self.functions.add(node.name)
        self.generic_visit(node)
        self.current_func = None

    def visit_Call(self, node):
        if self.current_func and isinstance(node.func, ast.Name) and node.func.id in self.functions:
            self.calls[self.current_func].append(node.func.id)
        self.generic_visit(node)

def has_cycle(graph):
    """DFS to detect cycles in a directed graph."""
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

def estimate_ram_usage(file_path):
    """
    Very rough heuristic to estimate how much RAM a Python file/module might occupy
    when loaded + parsed + turned into AST + held as objects.
    
    Factors considered (approximate):
    - Source code size
    - AST nodes (~10–30× source size in memory depending on complexity)
    - Bytecode + function objects + globals + etc.
    """
    try:
        file_size = os.path.getsize(file_path)
        
        # Rough multipliers (empirical / very approximate)
        # 1. Source code as string: ~1–1.5× file size
        # 2. AST: often 8–25× source size (tokens + objects)
        # 3. Bytecode + function objects: another 2–5×
        # → conservative total multiplier ~15–40×
        estimated = file_size * 25  # middle-ground heuristic
        
        # Add minimum floor (small files still take some base memory)
        estimated = max(estimated, 50_000)  # ~50 KB minimum
        
        # Cap for very large files (prevent absurd numbers)
        estimated = min(estimated, 500_000_000)  # 500 MB max per file estimate
        
        return estimated
    except Exception:
        return 0

def memory_space_data(directory_path):
    """
    Enhanced memory & object data:
    - File size (bytes)
    - Estimated RAM usage when loaded/parsed
    - Total project size & total estimated RAM
    - Call graph, recursive functions, classes
    """
    all_data = {}
    total_size_bytes = 0
    total_estimated_ram = 0
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                try:
                    file_size = os.path.getsize(full_path)
                    total_size_bytes += file_size
                    
                    est_ram = estimate_ram_usage(full_path)
                    total_estimated_ram += est_ram
                    
                    with open(full_path, "r", encoding="utf-8") as f:
                        source = f.read()
                    tree = ast.parse(source)
                    
                    visitor = CallGraphVisitor()
                    visitor.visit(tree)
                    graph = visitor.calls
                    
                    recursive_funcs = []
                    for func in graph:
                        if has_cycle({func: graph[func]}):
                            recursive_funcs.append(func)
                    
                    classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
                    
                    all_data[full_path] = {
                        "file_size_bytes": file_size,
                        "estimated_ram_bytes": est_ram,
                        "call_graph": dict(graph),
                        "recursive_functions": recursive_funcs,
                        "classes": classes
                    }
                except Exception as e:
                    all_data[full_path] = {
                        "error": str(e),
                        "file_size_bytes": 0,
                        "estimated_ram_bytes": 0
                    }
    
    # Add summary stats at top level
    all_data["__summary__"] = {
        "total_py_files_scanned": len([k for k in all_data if not k.startswith("__")]),
        "total_size_bytes": total_size_bytes,
        "total_size_human": f"{total_size_bytes / 1024 / 1024:.2f} MB",
        "total_estimated_ram_bytes": total_estimated_ram,
        "total_estimated_ram_human": f"{total_estimated_ram / 1024 / 1024:.2f} MB (very rough estimate)"
    }
    
    return all_data

if __name__ == "__main__":
    project_to_scan = "./project_test"  # Change this to your folder
    
    if not os.path.isdir(project_to_scan):
        print("Please provide a valid directory path.")
    else:
        # Optional: still generate AST view if needed
        # ast_data = ast_view(project_to_scan)
        # with open("ast_view.json", "w") as f:
        #     json.dump(ast_data, f, indent=4)
        # print("AST view data saved to ast_view.json")
        
        mem_data = memory_space_data(project_to_scan)
        with open("memory_space_data.json", "w", encoding="utf-8") as f:
            json.dump(mem_data, f, indent=2)
        print("Memory space data (with file sizes & RAM estimates) saved to memory_space_data.json")