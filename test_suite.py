import os
from fastapi.testclient import TestClient
from server import app

client = TestClient(app)

def test_all():
    print("=== 1. Testing Health & Root ===")
    r = client.get("/health")
    print("GET /health ->", r.status_code, r.json())
    assert r.status_code == 200

    r = client.get("/")
    print("GET / ->", r.status_code, "Length:", len(r.text))
    assert r.status_code == 200
    assert "Aegis SAST" in r.text

    print("\n=== 2. Testing Stats & Rules ===")
    r = client.get("/api/stats")
    print("GET /api/stats ->", r.status_code, "Rules count:", r.json()["total_rules"])
    assert r.status_code == 200

    print("\n=== 3. Testing Single Snippet Scanning ===")
    snippet_code = """
import subprocess

def run_cmd(user_arg):
    # Vulnerable
    subprocess.run("ls " + user_arg, shell=True)
"""
    r = client.post("/api/scan/code", json={"code": snippet_code, "filename": "test_cmd.py"})
    print("POST /api/scan/code ->", r.status_code)
    data = r.json()
    print("Total findings:", data["total_findings"], "Score:", data["score"])
    for f in data["findings"]:
        print(f"  [{f['severity']}] {f['category']} ({f['cwe']}) line {f['line']}")
    assert r.status_code == 200
    assert data["total_findings"] > 0

    print("\n=== 4. Testing Single File Scanning ===")
    target_file = "./project_test/mysite/mysite/settings.py"
    r = client.post("/api/scan/file", json={"file_path": target_file})
    print("POST /api/scan/file ->", r.status_code)
    data = r.json()
    print("File findings:", data["total_findings"], "Score:", data["score"])
    for f in data["findings"]:
        print(f"  [{f['severity']}] {f['category']} ({f['cwe']}) line {f['line']}")
    assert r.status_code == 200
    assert data["total_findings"] > 0

    print("\n=== 5. Testing Local Project Scanning ===")
    r = client.post("/api/scan/project", json={"project_path": "./project_test"})
    print("POST /api/scan/project ->", r.status_code)
    data = r.json()
    print("Total project findings:", data["total_findings"], "Score:", data["score"])
    print("Severity breakdown:", data["stats"])
    print("Categories:", data["categories_breakdown"])
    assert r.status_code == 200
    assert data["total_findings"] >= 4

    print("\n=== 6. Testing Data Access / AST & Memory ===")
    r = client.post("/api/data_access", json={"project_path": "./project_test", "include_ast": False})
    print("POST /api/data_access ->", r.status_code)
    mem_summary = r.json()["memory_space_data"]["__summary__"]
    print("Files scanned:", mem_summary["total_py_files_scanned"], "RAM estimate:", mem_summary["total_estimated_ram_human"])
    assert r.status_code == 200

    print("\n=== 7. Testing Filesystem Browser ===")
    r = client.get("/api/filesystem/browse?path=.")
    print("GET /api/filesystem/browse ->", r.status_code)
    fs_data = r.json()
    print("Found dirs:", len(fs_data["directories"]), "Python files:", len(fs_data["python_files"]))
    assert r.status_code == 200

    print("\nALL BACKEND & INTEGRATION TESTS PASSED PERFECTLY!")

if __name__ == "__main__":
    test_all()
