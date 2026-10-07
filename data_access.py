import ast
import os
import json
from collections import defaultdict
from typing import Dict, Any, List

def ast_to_dict(node, max_depth=8, current_depth=0):
    """Recursive conversion of AST node to dictionary for serialization, with depth limit to prevent circular explosion."""
    if current_depth > max_depth:
        return {"type": node.__class__.__name__ if isinstance(node, ast.AST) else str(node), "truncated": True}

    if not isinstance(node, ast.AST):
        if isinstance(node, (int, float, str, bool, type(None))):
            return node
        else:
            return str(node)

    d = {"type": node.__class__.__name__}
    
    # Include line numbers if available
    if hasattr(node, "lineno"):
        d["lineno"] = node.lineno
    if hasattr(node, "col_offset"):
        d["col_offset"] = node.col_offset

    for field, value in ast.iter_fields(node):
        if isinstance(value, list):
            d[field] = [ast_to_dict(v, max_depth, current_depth + 1) for v in value]
        elif isinstance(value, ast.AST):
            d[field] = ast_to_dict(value, max_depth, current_depth + 1)
        else:
            if isinstance(value, (int, float, str, bool, type(None))):
                d[field] = value
            else:
                d[field] = str(value)
    return d

def ast_view(directory_or_file_path: str):
    """Provides AST view data for a project directory or single file."""
    all_ast = {}
    
    if os.path.isfile(directory_or_file_path):
        try:
            with open(directory_or_file_path, "r", encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source)
            all_ast[directory_or_file_path] = ast_to_dict(tree)
        except Exception as e:
            all_ast[directory_or_file_path] = {"error": str(e)}
        return all_ast

    for root, dirs, files in os.walk(directory_or_file_path):
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
    """Visitor to build call graph for detecting recursion and function calls."""
    def __init__(self):
        self.functions = set()
        self.calls = defaultdict(list)
        self.current_func_stack = []

    def visit_FunctionDef(self, node):
        func_name = node.name
        self.functions.add(func_name)
        self.current_func_stack.append(func_name)
        self.generic_visit(node)
        self.current_func_stack.pop()

    def visit_AsyncFunctionDef(self, node):
        func_name = node.name
        self.functions.add(func_name)
        self.current_func_stack.append(func_name)
        self.generic_visit(node)
        self.current_func_stack.pop()

    def visit_Call(self, node):
        if self.current_func_stack:
            curr = self.current_func_stack[-1]
            called_name = None
            if isinstance(node.func, ast.Name):
                called_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                called_name = node.func.attr
            
            if called_name and called_name in self.functions:
                if called_name not in self.calls[curr]:
                    self.calls[curr].append(called_name)
        self.generic_visit(node)

def has_cycle(graph):
    """DFS to detect cycles in a directed graph."""
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

def estimate_ram_usage(file_size: int) -> int:
    """Heuristic to estimate RAM consumption for parsing + AST + bytecode."""
    estimated = file_size * 25
    estimated = max(estimated, 50_000)
    estimated = min(estimated, 500_000_000)
    return estimated

def analyze_source_ast_and_memory(source: str, filename: str = "<source>", include_ast: bool = False) -> Dict[str, Any]:
    """Analyzes AST, call graph, and memory footprint from source string."""
    try:
        file_size = len(source.encode("utf-8"))
        est_ram = estimate_ram_usage(file_size)
        tree = ast.parse(source)

        visitor = CallGraphVisitor()
        # First pass: collect all function names
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visitor.functions.add(node.name)
        visitor.visit(tree)
        graph = visitor.calls

        recursive_funcs = []
        for func in graph:
            if has_cycle({func: graph[func]}):
                recursive_funcs.append(func)

        classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        functions = list(visitor.functions)

        data = {
            "filename": filename,
            "file_size_bytes": file_size,
            "estimated_ram_bytes": est_ram,
            "call_graph": dict(graph),
            "recursive_functions": recursive_funcs,
            "classes": classes,
            "functions": functions
        }
        if include_ast:
            data["ast"] = ast_to_dict(tree)
        return data
    except Exception as e:
        return {
            "filename": filename,
            "error": str(e),
            "file_size_bytes": 0,
            "estimated_ram_bytes": 0,
            "call_graph": {},
            "recursive_functions": [],
            "classes": [],
            "functions": []
        }

def single_file_data(file_path: str, include_ast: bool = False) -> Dict[str, Any]:
    """Retrieves memory & AST data for a single file."""
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        return analyze_source_ast_and_memory(source, filename=file_path, include_ast=include_ast)
    except Exception as e:
        return {"error": str(e)}

def memory_space_data(directory_or_file_path: str):
    """
    Enhanced memory & object data for project or single file:
    - File size (bytes)
    - Estimated RAM usage
    - Total project size & total estimated RAM
    - Call graph, recursive functions, classes
    """
    if os.path.isfile(directory_or_file_path):
        data = single_file_data(directory_or_file_path)
        return {
            directory_or_file_path: data,
            "__summary__": {
                "total_py_files_scanned": 1,
                "total_size_bytes": data.get("file_size_bytes", 0),
                "total_size_human": f"{data.get('file_size_bytes', 0) / 1024:.2f} KB",
                "total_estimated_ram_bytes": data.get("estimated_ram_bytes", 0),
                "total_estimated_ram_human": f"{data.get('estimated_ram_bytes', 0) / 1024 / 1024:.2f} MB"
            }
        }

    all_data = {}
    total_size_bytes = 0
    total_estimated_ram = 0

    for root, dirs, files in os.walk(directory_or_file_path):
        for file in files:
            if file.endswith(".py"):
                full_path = os.path.join(root, file)
                try:
                    file_size = os.path.getsize(full_path)
                    total_size_bytes += file_size
                    est_ram = estimate_ram_usage(file_size)
                    total_estimated_ram += est_ram

                    with open(full_path, "r", encoding="utf-8") as f:
                        source = f.read()
                    
                    data = analyze_source_ast_and_memory(source, filename=full_path, include_ast=False)
                    all_data[full_path] = data
                except Exception as e:
                    all_data[full_path] = {
                        "error": str(e),
                        "file_size_bytes": 0,
                        "estimated_ram_bytes": 0
                    }

    all_data["__summary__"] = {
        "total_py_files_scanned": len([k for k in all_data if not k.startswith("__")]),
        "total_size_bytes": total_size_bytes,
        "total_size_human": f"{total_size_bytes / 1024 / 1024:.2f} MB",
        "total_estimated_ram_bytes": total_estimated_ram,
        "total_estimated_ram_human": f"{total_estimated_ram / 1024 / 1024:.2f} MB (rough estimate)"
    }

    return all_data


if __name__ == "__main__":
    project_to_scan = "./project_test"
    if not os.path.isdir(project_to_scan):
        print("Please provide a valid directory path.")
    else:
        mem_data = memory_space_data(project_to_scan)
        print(f"Scanned {mem_data['__summary__']['total_py_files_scanned']} files. Total RAM estimate: {mem_data['__summary__']['total_estimated_ram_human']}")