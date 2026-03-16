import os
import subprocess
from dotenv import load_dotenv

# Load .env file
load_dotenv()

PASSWORD = os.getenv("TRUENAS_PASSWORD")

if PASSWORD is None:
    raise RuntimeError("TRUENAS_PASSWORD not found in .env")

def run(cmd, password=None):
    if password:
        subprocess.run(cmd, input=password + "\n", text=True, check=True)
    else:
        subprocess.run(cmd, check=True)

def get_cpu_model():
    with open("/proc/cpuinfo") as f:
        for line in f:
            if "model name" in line:
                return line.split(":", 1)[1].strip()

# 1. create logs directory if it does not exist
if not os.path.isdir("./logs"):
    os.makedirs("./logs", exist_ok=True)

# 2. mount sshfs to ./logs
run([
    "sudo",
    "sshfs",
    "-o", "allow_other,password_stdin",
    "project01@cave.inf.ethz.ch:/mnt/SECTRS_POOL_0/USERDATA/BENEDICT/PROJECT_IBS",
    "./logs"
], PASSWORD)

cpu_model = get_cpu_model()

# 3. mount local SSD
if "AMD EPYC 7313 16-Core Processor" in cpu_model:
    subprocess.run([
        "sudo",
        "mount",
        "/dev/sda2",
        "/mnt/ssd/"
    ], check=True)

    
# 4. mount truenas via sshfs
run([
    "sudo",
    "sshfs",
    "-o", "password_stdin",
    "project01@cave.inf.ethz.ch:/mnt/SECTRS_POOL_0/USERDATA/BENEDICT/PROJECT_IBS",
    "/mnt/truenas"
], PASSWORD)

print("All mounts completed.")