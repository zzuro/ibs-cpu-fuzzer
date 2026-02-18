import os
import sys
import subprocess
import threading
from pathlib import Path

QEMU_PATTERN = "qemu-system-x86_64"
KVMTOOL_PATTERN = "lkvm"
SAMPLER_PATH = "./sampling"
LOG_FILE = "sampling.log"

# Global lock for synchronized file writes
log_lock = threading.Lock()
TID_COUNT = 0

def find_qemu_pid() -> str:
    try:
        output = subprocess.check_output(["pgrep", "-f", KVMTOOL_PATTERN], text=True)
        pids = [p.strip() for p in output.splitlines() if p.strip()]
        if not pids:
            raise subprocess.CalledProcessError(1, "pgrep")
        return pids[0]
    except subprocess.CalledProcessError:
        print(f"Could not find {QEMU_PATTERN} process")
        sys.exit(1)


def get_tids(pid: str) -> list[str]:
    task_dir = Path(f"/proc/{pid}/task")
    if not task_dir.exists():
        print(f"Process {pid} no longer exists")
        sys.exit(1)

    return sorted([p.name for p in task_dir.iterdir() if p.is_dir()], key=int)


def run_sampling_for_tid(tid: str) -> None:
    global TID_COUNT
    cmd = ["sudo", SAMPLER_PATH, tid]

    try:
        res = subprocess.run(cmd, text=True, capture_output=True)

        if res.stdout.strip() != "":
            with log_lock:
                TID_COUNT += 1
                with open(LOG_FILE, "a") as f:
                    f.write(f"\n===== TID {tid} =====\n")

                    if res.stdout:
                        f.write(res.stdout)

                    if res.stderr:
                        f.write("\n--- STDERR ---\n")
                        f.write(res.stderr)

                    f.write("\n")

    except FileNotFoundError:
        print(f"Sampler not found: {SAMPLER_PATH}")
        sys.exit(1)


def main():
    global TID_COUNT
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    pid = find_qemu_pid()
    tids = get_tids(pid)

    print(f"QEMU PID: {pid}")
    print(f"Found {len(tids)} TIDs: {', '.join(tids)}")
    threads = []
    for tid in tids:
        t = threading.Thread(target=run_sampling_for_tid, args=(tid,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    with open(LOG_FILE, "a") as f:
        f.write(f"\nTotal TIDs sampled: {TID_COUNT}\n")

if __name__ == "__main__":
    main()
