import os, hashlib, time
TRANSCRIPT_DIR = "transcripts"
os.makedirs(TRANSCRIPT_DIR, exist_ok=True)

def append_lines(lines, filename=None):
    filename = filename or f"transcript_{int(time.time())}.log"
    path = os.path.join(TRANSCRIPT_DIR, filename)
    with open(path, "a") as f:
        for l in lines:
            f.write(l.rstrip("\n") + "\n")
    return path

def sha256_of_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def read_lines(path):
    with open(path,"r") as f: return [l.rstrip("\n") for l in f.readlines()]
