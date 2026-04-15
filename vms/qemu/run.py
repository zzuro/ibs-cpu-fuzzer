import subprocess
import time

CMD = ["sudo", "taskset", "-c", "4", "./sandsifter.sh"]
RUNS = 20

for i in range(RUNS):
    print(f"Run {i+1}/{RUNS}")

    proc = subprocess.Popen(CMD)

    time.sleep(2)

    proc.kill()

    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()

    time.sleep(1)

print("Done.")