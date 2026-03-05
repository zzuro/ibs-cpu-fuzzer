#!/usr/bin/env python3
from ioctl import _ioctl, _IOR, _IOW
from fuzz_state import *

import argparse
import os
import re
import sys
import shutil
import signal
import struct
import subprocess
import time
import select
from pathlib import Path
import ctypes
import shlex
import csv

# later we will want to use all CPUs

LOG_DIR = Path("/mnt/home/avezzu/ibs_log")
IBS_PREFIX = str(LOG_DIR / "ibs_")
IBS_SUFFIX = ".csv"

DEVICE_NAME = "/dev/svm_ibs_dev"
MAX_INSN_LENGTH = 15


FUZZ_IOC_GET_STATE = _IOR(ord('a'), ord('c'), FuzzerState)  # _IOR('a','c', fuzzer_state_t)
FUZZ_IOC_SET_STATE = _IOW(ord('a'), ord('d'), FuzzerState)  # _IOW('a','d', fuzzer_state_t)


# ----------------------------
# Helpers: logging + tracing
# ----------------------------
def reset_log_directory():
    if LOG_DIR.exists():
        shutil.rmtree(LOG_DIR)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

def last_activity_time() -> float:
    last_modified = LOG_DIR.stat().st_mtime   
    seconds_since_modified = time.time() - last_modified
    return seconds_since_modified

def find_latest_file() -> Path:
    latest_file = None
    latest_mtime = 0.0

    for entry in LOG_DIR.iterdir():
        if entry.is_file() and entry.name.startswith("ibs_") and entry.name.endswith(".csv"):
            mtime = entry.stat().st_mtime
            if mtime > latest_mtime:
                latest_mtime = mtime
                latest_file = entry

    return latest_file

# ----------------------------
# Helpers: device state I/O
# ----------------------------

def open_device() -> int:
    fd = os.open(DEVICE_NAME, os.O_RDWR)
    return fd

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


def default_reset_state() -> FuzzerState:
    st = FuzzerState()

    st.total_range.start.len = 0
    st.total_range.end.len = 0
    for i in range(MAX_INSN_LENGTH):
        st.total_range.start.bytes[i] = 0x00
        st.total_range.end.bytes[i] = 0xFF

    st.total_range.started = False

    st.inj.i.len = 1
    st.inj.index = 0
    st.inj.last_len = 0

    st.current_op = START
    st.fetch_counter = 0
    st.per_instruction_counter = 0
    st.file_open = False

    return st

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
        return f"len={insn.len} bytes=" + " ".join(f"{x:02x}" for x in b)

    print("========== FUZZER STATE ==========")

    # pointers
    print("Pointers:")
    print(f"  fuzz_mem1_host : 0x{st.fuzz_mem1_host or 0:016x}")
    print(f"  fuzz_mem1_guest: 0x{st.fuzz_mem1_guest or 0:016x}")
    print(f"  fuzz_mem2_host : 0x{st.fuzz_mem2_host or 0:016x}")
    print(f"  fuzz_mem2_guest: 0x{st.fuzz_mem2_guest or 0:016x}")
    print()

    # range
    print("Total Range:")
    print(f"  start   : {insn_to_str(st.total_range.start)}")
    print(f"  end     : {insn_to_str(st.total_range.end)}")
    print(f"  started : {bool(st.total_range.started)}")
    print()

    # injection
    print("Injection:")
    print(f"  insn     : {insn_to_str(st.inj.i)}")
    print(f"  index    : {st.inj.index}")
    print(f"  last_len : {st.inj.last_len}")
    print()

    # result
    print("Result:")
    print(f"  valid     : {st.result.valid}")
    print(f"  length    : {st.result.length}")
    print(f"  ecxeption : {st.result.ecxeption}")
    print()

    # misc
    print("Execution:")
    op_map = {0: "START", 1: "INSTRUCTION", 2: "MICROOP"}
    print(f"  current_op    : {op_map.get(st.current_op, st.current_op)}")
    print(f"  current_length: {st.current_length}")
    print(f"  fetch_counter : {st.fetch_counter}")
    print(f"  file_open     : {bool(st.file_open)}")
    print()

    # minimal useful VMCB snapshot
    print("Saved CPU State (VMCB excerpt):")
    print(f"  RIP     : 0x{st.saved_state.rip:016x}")
    print(f"  RSP     : 0x{st.saved_state.rsp:016x}")
    print(f"  RAX     : 0x{st.saved_state.rax:016x}")
    print(f"  RFLAGS  : 0x{st.saved_state.rflags:016x}")
    print(f"  CR0     : 0x{st.saved_state.cr0:016x}")
    print(f"  CR3     : 0x{st.saved_state.cr3:016x}")
    print(f"  CR4     : 0x{st.saved_state.cr4:016x}")
    print(f"  EFER    : 0x{st.saved_state.efer:016x}")
    print("==================================")


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


def start_qemu(cmd: list[str]) -> subprocess.Popen:
    return subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,   
        stdout=sys.stdout,
        stderr=sys.stderr,
        start_new_session=True,    
    )

def kill_qemu(proc: subprocess.Popen, sig=signal.SIGTERM, grace_sec: float = 2.0) -> None:
    if proc.poll() is not None:
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
# Main trace loop with timeout
# ----------------------------

def log_timeout_instruction(crash_log_path: Path, insn_bytes: bytes, note: str = "trace_pipe inactivity timeout") -> None:
    crash_log_path.parent.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    insn_hex = insn_bytes.hex() if insn_bytes else "UNKNOWN"
    # one-line append
    with open(crash_log_path, "a", buffering=1) as fp:
        fp.write(f"[{ts}] {note} insn={insn_hex}\n")


def trace_loop_with_timeout(
    device_fd: int,
    qemu_proc: subprocess.Popen,
    inactivity_timeout: float,
    on_timeout_state_path: Path,
    resume: bool = False,
    qemu_script : Path = None
) -> int:
    try:
        if not resume:
            reset_log_directory()
    except Exception as e:
        print(f"Failed to reset log directory: {e}", file=sys.stderr)
        return 1

    crash_log = LOG_DIR / "timeouts.log"

    print(f"Starting fuzzer... (inactivity timeout: {inactivity_timeout}s)", file=sys.stderr)

    try:
        while True:

            # inactivity timeout check, try to restart
            if last_activity_time() >= inactivity_timeout:
                print(f"TIMEOUT: no trace_pipe activity for {inactivity_timeout}s", file=sys.stderr)
                try:
                    instr = find_latest_file().name[len("ibs_"):-len(".csv")]
                    log_timeout_instruction(crash_log, instr)
                    print(f"Logged timeout instruction to {crash_log}", file=sys.stderr)
                except Exception as e:
                    print(f"WARN: failed to log timeout instruction: {e}", file=sys.stderr)
                try:
                    st = ioctl_get_state(device_fd)
                    dump_state_to_file(st, on_timeout_state_path)
                    print(f"Saved fuzz_state to {on_timeout_state_path}", file=sys.stderr)
                except Exception as e:
                    print(f"ERROR: failed to GET/DUMP state on timeout: {e}", file=sys.stderr)

                if qemu_proc is not None:
                    print("Stopping QEMU ...", file=sys.stderr)
                    kill_qemu(qemu_proc)

                try:
                    qemu_proc = start_qemu(parse_qemu_script(qemu_script)) 
                    print(f"Restarted QEMU (pid={qemu_proc.pid})", file=sys.stderr)
                except Exception as e:
                    print(f"ERROR: failed to restart QEMU: {e}", file=sys.stderr)
                    return 2  # can't proceed without qemu
                
                continue

            
    except KeyboardInterrupt:
        if qemu_proc is not None:
            print("Stopping QEMU ...", file=sys.stderr)
            kill_qemu(qemu_proc)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu-script", default="./../vms/qemu.sh", help="Path to qemu start script")
    ap.add_argument("--timeout", type=float, default=30.0, help="Inactivity timeout (seconds) on trace_pipe; 0 disables")
    ap.add_argument("--state-file", default="/mnt/home/avezzu/ibs_log/fuzz_state.bin",
                    help="Where to dump fuzz_state on timeout (and/or for periodic dumps)")
    ap.add_argument("--resume", action="store_true",
                    help="Resume from --state-file instead of resetting to defaults")
    ap.add_argument("--no-qemu", action="store_true", help="Do not start QEMU (debug)")
    args = ap.parse_args()

    try:
        dev_fd = open_device()
    except OSError as e:
        print(f"Failed to open {DEVICE_NAME}: {e}", file=sys.stderr)
        return 1

    state_path = Path(args.state_file)

    try:
        if args.resume:
            st = load_state_from_file(state_path)
            ioctl_set_state(dev_fd, st)
            print(f"Resumed fuzz_state from {state_path}", file=sys.stderr)
        else:
            st = default_reset_state()
            ioctl_set_state(dev_fd, st)
            print("Fuzzer state reset successfully.", file=sys.stderr)
    except Exception as e:
        print(f"Failed to SET state: {e}", file=sys.stderr)
        os.close(dev_fd)
        return 1

    qemu_proc = None
    qemu_script = None
    if not args.no_qemu:
        qemu_script = Path(args.qemu_script)
        try:
            qemu_proc = start_qemu(parse_qemu_script(qemu_script))
            print(f"Started QEMU via {qemu_script} (pid={qemu_proc.pid})", file=sys.stderr)
        except Exception as e:
            print(f"Failed to start QEMU: {e}", file=sys.stderr)
            os.close(dev_fd)
            return 1

    rc = trace_loop_with_timeout(
        device_fd=dev_fd,
        qemu_proc=qemu_proc,
        inactivity_timeout=args.timeout,
        on_timeout_state_path=state_path,
        resume=args.resume,
        qemu_script=qemu_script
    )

    try:
        if qemu_proc is not None and qemu_proc.poll() is None:
            kill_qemu(qemu_proc)
    except Exception:
        pass

    try:
        os.close(dev_fd)
    except Exception:
        pass

    return rc


if __name__ == "__main__":
    raise SystemExit(main())