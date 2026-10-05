from pathlib import Path

root = Path("/mnt/data")
print("Files:", list(root.rglob("*")))

script = root / "test.py"
print("test.py exists:", script.exists())
if script.exists():
    print(script.read_text())
