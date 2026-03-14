#!/usr/bin/env python3
from ioctl import _ioctl, _IOR, _IOW, _IO
from fuzz_state import *
from relayfs import *

import argparse
import os
import sys
import shutil
import signal
import subprocess
import time
from pathlib import Path
import ctypes
import shlex
import errno
import threading
import traceback


SSD_DIR = Path("/mnt/truenas/")
LOG_DIR = Path("/mnt/truenas/ibs_log")
IBS_PREFIX = str(LOG_DIR / "ibs_")
IBS_SUFFIX = ".bin"

DEVICE_NAME = "/dev/svm_ibs_dev"
MAX_INSN_LENGTH = 15

TRACE_BASE = "/sys/kernel/debug/ibs_logger/cpu"
POLL_SLEEP_SEC = 0.05
BIN_BUFFER_SIZE = 1024 * 1024

FUZZ_IOC_GET_STATE = _IOR(ord('a'), ord('c'), FuzzerState)
FUZZ_IOC_SET_STATE = _IOW(ord('a'), ord('d'), FuzzerState)
FUZZ_IOC_OPEN_LOG = _IO(ord('a'), ord('e'))
FUZZ_IOC_CLOSE_LOG = _IO(ord('a'), ord('f'))
FUZZ_IOC_MOVE_NEXT_INSTR = _IO(ord('a'), ord('g'))
FUZZ_IOC_RESET_STATE = _IO(ord('a'), ord('i'))

stop_event = threading.Event()
print_lock = threading.Lock()


# ----------------------------
# Thread-safe printing
# ----------------------------

def ts_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

def ts_print_exc():
    with print_lock:
        traceback.print_exc(file=sys.stderr)


# ----------------------------
# Helpers: logging + tracing
# ----------------------------

def check_ssd_mounted() -> bool:
    return SSD_DIR.is_dir() and os.access(SSD_DIR, os.W_OK)

def reset_log_directory():
    if LOG_DIR.exists():
        shutil.rmtree(LOG_DIR)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

def count_log_files() -> int:
    if not LOG_DIR.exists():
        ts_print("Log directory does not exist", file=sys.stderr)
        return 0

    files = [f for f in LOG_DIR.iterdir() if f.is_file()]
    total = len(files)
    avg_size = sum(f.stat().st_size for f in files) / total if total > 0 else 0
    ts_print(f"Log directory contains {total} files, average size: {avg_size:.2f} bytes", file=sys.stderr)
    return total

def create_log_directory_if_missing():
    if not LOG_DIR.exists():
        LOG_DIR.mkdir(parents=True, exist_ok=True)

def check_disk_space():
    _, _, free = shutil.disk_usage(SSD_DIR)
    return free >= 10 * 1024**3

def generate_filename(insn_bytes: bytes) -> str:
    encoded = "".join(f"\\x{b:02x}" for b in insn_bytes)
    return f"{IBS_PREFIX}{encoded}{IBS_SUFFIX}"

def read_exact_or_none(f, n: int) -> bytes | None:
    chunks = []
    total = 0

    while total < n:
        if stop_event.is_set():
            return None

        try:
            chunk = f.read(n - total)
        except OSError as e:
            if e.errno == errno.EIO:
                return None
            raise

        if not chunk:
            return None

        chunks.append(chunk)
        total += len(chunk)

    return b"".join(chunks)


# ----------------------------
# Per-thread record handling
# ----------------------------

class WorkerContext:
    def __init__(self, core_id: int):
        self.core_id = core_id


# ----------------------------
# Helpers: device state I/O
# ----------------------------

def open_device() -> int:
    return os.open(DEVICE_NAME, os.O_RDWR)

def ioctl_set_state(fd: int, st: FuzzerState) -> None:
    rc = _ioctl(fd, FUZZ_IOC_SET_STATE, ctypes.byref(st))
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(SET_STATE) failed: {os.strerror(e)}")

def ioctl_get_state(fd: int) -> FuzzerState:
    st = FuzzerState()
    rc = _ioctl(fd, FUZZ_IOC_GET_STATE, ctypes.byref(st))
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(GET_STATE) failed: {os.strerror(e)}")
    return st

def ioctl_open_log(fd: int) -> None:
    rc = _ioctl(fd, FUZZ_IOC_OPEN_LOG, None)
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(OPEN_LOG) failed: {os.strerror(e)}")

def ioctl_close_log(fd: int) -> None:
    rc = _ioctl(fd, FUZZ_IOC_CLOSE_LOG, None)
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(CLOSE_LOG) failed: {os.strerror(e)}")

def ioctl_move_next_instr(fd: int) -> None:
    rc = _ioctl(fd, FUZZ_IOC_MOVE_NEXT_INSTR, None)
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(MOVE_NEXT_INSTR) failed: {os.strerror(e)}")
    
def ioctl_reset_state(fd: int) -> None:
    rc = _ioctl(fd, FUZZ_IOC_RESET_STATE, None)
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(RESET_STATE) failed: {os.strerror(e)}")

def default_reset_state() -> FuzzerState:
    st = FuzzerState()

    st.search_range.start.len = 0
    st.search_range.end.len = 0
    for i in range(MAX_INSN_LENGTH):
        st.search_range.start.bytes[i] = 0x00
        st.search_range.end.bytes[i] = 0xFF

    st.search_range.started = False

    st.inj.i.len = 1
    st.inj.index = 0
    st.inj.last_len = 0

    st.current_op = START
    st.fetch_counter = 0
    st.per_instruction_counter = 0
    st.file_open = False

    return st

def save_state(fd: int, path: Path):
    st = ioctl_get_state(fd)
    dump_state_to_file(st, path)

def dump_state_to_file(st: FuzzerState, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = ctypes.string_at(ctypes.byref(st), ctypes.sizeof(st))
    path.write_bytes(raw)

def load_state_from_file(path: Path) -> FuzzerState:
    raw = path.read_bytes()
    if len(raw) != ctypes.sizeof(FuzzerState):
        raise ValueError(
            f"Bad state file size: got {len(raw)} bytes, expected {ctypes.sizeof(FuzzerState)}"
        )
    st = FuzzerState()
    ctypes.memmove(ctypes.byref(st), raw, len(raw))
    return st

def dump_fuzzer_state_pretty(st: FuzzerState) -> None:
    def insn_to_str(insn):
        b = bytes(insn.bytes[:insn.len])
        return f"len={insn.len} bytes=" + " ".join(f"\\{x:02x}" for x in b)

    ts_print("========== FUZZER STATE ==========")
    ts_print("Pointers:")
    ts_print(f"  fuzz_mem1_host : 0x{st.fuzz_mem1_host or 0:016x}")
    ts_print(f"  fuzz_mem1_guest: 0x{st.fuzz_mem1_guest or 0:016x}")
    ts_print(f"  fuzz_mem2_host : 0x{st.fuzz_mem2_host or 0:016x}")
    ts_print(f"  fuzz_mem2_guest: 0x{st.fuzz_mem2_guest or 0:016x}")
    ts_print()

    ts_print("Total Range:")
    ts_print(f"  started : {bool(st.total_range.started)}")
    ts_print()

    ts_print("Injection:")
    ts_print(f"  insn     : {insn_to_str(st.inj.i)}")
    ts_print(f"  index    : {st.inj.index}")
    ts_print(f"  last_len : {st.inj.last_len}")
    ts_print()

    ts_print("Result:")
    ts_print(f"  valid     : {st.result.valid}")
    ts_print(f"  length    : {st.result.length}")
    ts_print(f"  ecxeption : {st.result.ecxeption}")
    ts_print()

    ts_print("Execution:")
    op_map = {0: "START", 1: "INSTRUCTION", 2: "MICROOP"}
    ts_print(f"  current_op    : {op_map.get(st.current_op)}")
    ts_print(f"  fetch_counter : {st.fetch_counter}")
    ts_print(f"  file_open     : {bool(st.file_open)}")
    ts_print()

    ts_print("Saved CPU State (VMCB excerpt):")
    ts_print(f"  RIP     : 0x{st.saved_state.rip:016x}")
    ts_print(f"  RSP     : 0x{st.saved_state.rsp:016x}")
    ts_print(f"  RAX     : 0x{st.saved_state.rax:016x}")
    ts_print(f"  RFLAGS  : 0x{st.saved_state.rflags:016x}")
    ts_print(f"  CR0     : 0x{st.saved_state.cr0:016x}")
    ts_print(f"  CR3     : 0x{st.saved_state.cr3:016x}")
    ts_print(f"  CR4     : 0x{st.saved_state.cr4:016x}")
    ts_print(f"  EFER    : 0x{st.saved_state.efer:016x}")
    ts_print("==================================")


# ----------------------------
# QEMU control
# ----------------------------

def parse_qemu_script(script_path: Path) -> list[str]:
    content = script_path.read_text()
    content = content.replace("\\\n", " ")

    lines = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)

    command_str = " ".join(lines)
    return shlex.split(command_str)

def start_qemu(cmd: list[str], core_id: int) -> subprocess.Popen:
    return subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

def kill_qemu(proc: subprocess.Popen, sig=signal.SIGTERM, grace_sec: float = 2.0) -> None:
    if proc is None or proc.poll() is not None:
        return

    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return

    t0 = time.time()
    while time.time() - t0 < grace_sec:
        if proc.poll() is not None:
            return
        time.sleep(0.05)

    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


# ----------------------------
# Main per-core trace loop
# ----------------------------

def log_timeout_instruction(crash_log_path: Path, insn_bytes: bytes, note: str = "trace inactivity timeout") -> None:
    crash_log_path.parent.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    insn_hex = insn_bytes.hex() if insn_bytes else "UNKNOWN"
    with open(crash_log_path, "a", buffering=1) as fp:
        fp.write(f"[{ts}] {note} insn={insn_hex}\n")

def trace_loop_with_timeout(
    core_id: int,
    device_fd: int,
    qemu_proc: subprocess.Popen,
    inactivity_timeout: float,
    on_timeout_state_path: Path,
    resume: bool,
    qemu_script: Path
) -> int:
    trace_path = f"{TRACE_BASE}{core_id}/trace{core_id}"
    ctx = WorkerContext(core_id)

    crash_log = LOG_DIR / f"timeouts_core{core_id}.log"

    try:
        relay_fd = open(trace_path, "rb", buffering=0)
    except Exception as e:
        ts_print(f"[core {core_id}] Failed to open {trace_path}: {e}", file=sys.stderr)
        return 1

    last_received = time.monotonic()
    ts_print(f"[core {core_id}] Starting trace loop on {trace_path} (timeout={inactivity_timeout}s)", file=sys.stderr)

    current_insn_bytes = None
    out = None

    try:
        while not stop_event.is_set():
            now = time.monotonic()

            if inactivity_timeout > 0 and (now - last_received >= inactivity_timeout):
                try:
                    st = ioctl_get_state(device_fd)
                    dump_state_to_file(st, on_timeout_state_path)
                    ts_print(f"[core {core_id}] Saved fuzz_state to {on_timeout_state_path}", file=sys.stderr)
                except Exception as e:
                    st = None
                    ts_print(f"[core {core_id}] ERROR: failed to GET/DUMP state on timeout: {e}", file=sys.stderr)

                ts_print(f"[core {core_id}] TIMEOUT: no activity for {inactivity_timeout}s", file=sys.stderr)

                try:
                    if st is not None:
                        log_timeout_instruction(crash_log, bytes(st.inj.i.bytes[:st.inj.i.len]))
                    else:
                        log_timeout_instruction(crash_log, b"", note="timeout (state unavailable)")
                except Exception as e:
                    ts_print(f"[core {core_id}] WARN: failed to log timeout instruction: {e}", file=sys.stderr)

                if qemu_proc is not None:
                    ts_print(f"[core {core_id}] Stopping QEMU ...", file=sys.stderr)
                    kill_qemu(qemu_proc)

                try:
                    ioctl_move_next_instr(device_fd)
                except Exception as e:
                    ts_print(f"[core {core_id}] ERROR: failed to rotate instruction/log after timeout: {e}", file=sys.stderr)
                    relay_fd.close()
                    return 2

                try:
                    qemu_proc = start_qemu(parse_qemu_script(qemu_script), core_id)
                    ts_print(f"[core {core_id}] Restarted QEMU (pid={qemu_proc.pid})", file=sys.stderr)
                except Exception as e:
                    ts_print(f"[core {core_id}] ERROR: failed to restart QEMU: {e}", file=sys.stderr)
                    relay_fd.close()
                    return 2

                if out is not None:
                    out.close()
                    out = None

                current_insn_bytes = None
                last_received = time.monotonic()
                continue

            header_blob = read_exact_or_none(relay_fd, HEADER_SIZE)
            if header_blob is None:
                time.sleep(POLL_SLEEP_SEC)
                continue

            hdr = IbsRecordHeader.from_buffer_copy(header_blob)
            if hdr.record_len < HEADER_SIZE:
                try:
                    st = ioctl_get_state(device_fd)
                    dump_state_to_file(st, on_timeout_state_path)
                except Exception:
                    pass
                ts_print(f"[core {core_id}] WARN: malformed record with len={hdr.record_len}, skipping", file=sys.stderr)
                continue

            if hdr.record_type == IBS_REC_FINISH or not check_disk_space():
                if not check_disk_space():
                    ts_print(f"[core {core_id}] ERROR: disk space low, stopping.", file=sys.stderr)
                else:
                    ts_print(f"[core {core_id}] Received FINISH record, stopping.", file=sys.stderr)

                if out is not None:
                    out.close()
                if qemu_proc is not None:
                    ts_print(f"[core {core_id}] Stopping QEMU ...", file=sys.stderr)
                    kill_qemu(qemu_proc)
                relay_fd.close()
                return 0

            insn_bytes = bytes(hdr.instruction[:hdr.instruction_len])
            if current_insn_bytes != insn_bytes:
                current_insn_bytes = insn_bytes
                current_path = generate_filename(current_insn_bytes)
                if out is not None:
                    out.close()
                out = open(current_path, "ab", buffering=BIN_BUFFER_SIZE)

            remaining = hdr.record_len - HEADER_SIZE
            body_blob = read_exact_or_none(relay_fd, remaining)
            if body_blob is None:
                time.sleep(POLL_SLEEP_SEC)
                continue

            full_blob = header_blob + body_blob
            last_received = time.monotonic()

            if hdr.record_type == IBS_REC_HPA:
                if hdr.record_len != HPA_SIZE:
                    ts_print(f"[core {core_id}] WARN: malformed HPA record with len={hdr.record_len}, skipping", file=sys.stderr)
                    continue

            elif hdr.record_type == IBS_REC_EVENT:
                if hdr.record_len != EVENT_SIZE:
                    raise ValueError(
                        f"[core {core_id}] EVENT record size mismatch: got {hdr.record_len}, expected {EVENT_SIZE}"
                    )

            else:
                ts_print(f"[core {core_id}] WARN: unknown record type {hdr.record_type}, skipping", file=sys.stderr)
                continue

            out.write(full_blob)

    except KeyboardInterrupt:
        stop_event.set()
    finally:
        if out is not None:
            try:
                out.close()
            except Exception:
                pass
        try:
            relay_fd.close()
        except Exception:
            pass
        if qemu_proc is not None:
            kill_qemu(qemu_proc)

    return 0


# ----------------------------
# Worker
# ----------------------------

def core_worker(core_id: int, args) -> None:
    dev_fd = open_device()
    qemu_proc = None

    os.sched_setaffinity(0, {core_id})
    state_path = Path(str(args.state_file).replace(".bin", f".core{core_id}.bin"))
    qemu_script = Path(args.qemu_script)

    try:
        if args.resume:
            st = load_state_from_file(state_path)
            ioctl_set_state(dev_fd, st)
            create_log_directory_if_missing()
            ts_print(f"[core {core_id}] Resumed fuzz_state from {state_path}", file=sys.stderr)
        else:
            st = default_reset_state()
            ioctl_set_state(dev_fd, st)
            ts_print(f"[core {core_id}] Fuzzer state reset successfully.", file=sys.stderr)

        qemu_proc = start_qemu(parse_qemu_script(qemu_script), core_id)
        ts_print(f"[core {core_id}] Started QEMU via {qemu_script} (pid={qemu_proc.pid})", file=sys.stderr)

        trace_loop_with_timeout(
            core_id=core_id,
            device_fd=dev_fd,
            qemu_proc=qemu_proc,
            inactivity_timeout=args.timeout,
            on_timeout_state_path=state_path,
            resume=args.resume,
            qemu_script=qemu_script
        )

    except Exception as e:
        ts_print(f"[core {core_id}] Worker failed: {e}", file=sys.stderr)
        ts_print_exc()
        stop_event.set()

    finally:
        if qemu_proc is not None:
            try:
                kill_qemu(qemu_proc)
            except Exception:
                pass
        if dev_fd is not None:
            try:
                os.close(dev_fd)
            except Exception:
                pass


# ----------------------------
# Main
# ----------------------------

def get_available_cores() -> list[int]:
    try:
        return sorted(os.sched_getaffinity(0))
    except Exception:
        n = os.cpu_count() or 1
        return list(range(n))

def signal_handler(sig, frame):
    ts_print("\nReceived Ctrl+C, stopping all workers...", file=sys.stderr)
    stop_event.set()

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu-script", default="./../vms/qemu.sh", help="Path to qemu start script")
    ap.add_argument("--timeout", type=float, default=10.0, help="Inactivity timeout (seconds); 0 disables")
    ap.add_argument("--state-file", default="/mnt/truenas/ibs_log/fuzz_state.bin",
                    help="Base path used to dump fuzz_state on timeout; per-core suffix is added")
    ap.add_argument("--resume", action="store_true",
                    help="Resume from per-core state files instead of resetting to defaults")
    ap.add_argument(
        "--save-state",
        nargs="?",
        const="/mnt/truenas/ibs_log/fuzz_state.bin",
        default=None,
        help="Save fuzz state for all selected cores and exit"
    )
    ap.add_argument("--count-only", action="store_true", help="Only count records and exit")
    ap.add_argument("--cores", default=None,
                    help="Comma-separated core list, e.g. 0,1,2,3. Default: all available cores")

    args = ap.parse_args()

    if args.count_only:
        count_log_files()
        return 0

    if args.cores:
        cores = sorted({int(x.strip()) for x in args.cores.split(",") if x.strip()})
    else:
        cores = get_available_cores()

    ts_print(f"Using cores: {cores}", file=sys.stderr)

    if args.save_state:
        base_path = Path(args.save_state)
        had_error = False

        for core_id in cores:
            dev_fd = None
            try:
                os.sched_setaffinity(0, {core_id})
                dev_fd = open_device()

                core_state_path = Path(str(base_path).replace(".bin", f".core{core_id}.bin"))
                save_state(dev_fd, core_state_path)
                ts_print(f"[core {core_id}] Saved fuzz_state to {core_state_path}", file=sys.stderr)

            except Exception as e:
                had_error = True
                ts_print(f"[core {core_id}] Failed to save state: {e}", file=sys.stderr)

            finally:
                if dev_fd is not None:
                    try:
                        os.close(dev_fd)
                    except Exception:
                        pass

        return 1 if had_error else 0

    try:
        subprocess.run(
            ["sudo", "killall", "qemu-system-x86_64"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )
    except Exception as e:
        ts_print(f"Warning: failed to kill existing qemu instances: {e}", file=sys.stderr)

    device_fd = open_device()
    if not args.resume:
        try:
            reset_log_directory()
            ioctl_reset_state(device_fd)
        except Exception as e:
            ts_print(f"Failed to reset log directory: {e}", file=sys.stderr)
            return 1
    else:
        create_log_directory_if_missing()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        ioctl_close_log(device_fd)
    except Exception:
        pass

    ioctl_open_log(device_fd)
    os.close(device_fd)

    threads = []
    for core_id in cores:
        t = threading.Thread(target=core_worker, args=(core_id, args), name=f"core-{core_id}", daemon=True)
        t.start()
        threads.append(t)

    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.2)
            if stop_event.is_set():
                break
    except KeyboardInterrupt:
        stop_event.set()

    for t in threads:
        t.join()

    return 0

if __name__ == "__main__":
    if not check_ssd_mounted():
        ts_print(f"ERROR: SSD directory {SSD_DIR} is not mounted or writable.", file=sys.stderr)
        raise SystemExit(1)

    raise SystemExit(main())