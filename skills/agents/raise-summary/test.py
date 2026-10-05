import os

print("cwd:", os.getcwd())
print("root:", os.listdir("/"))
print("/mnt:", os.listdir("/mnt") if os.path.exists("/mnt") else "NO /mnt")
print("/mnt/data:", os.listdir("/mnt/data") if os.path.exists("/mnt/data") else "NO /mnt/data")

