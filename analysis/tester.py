import sys
import os
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
import json
import re

sys.path.append(str(Path(__file__).resolve().parent.parent))

from fuzzer.fuzz_state import FuzzerState, INSTRUCTION
from fuzzer.ioctl import _IOR, _IOW, _IO, _ioctl
from fuzzer.relayfs import IbsRecordHeader, IbsHpaRecord, IbsEventRecord, IBS_OP_LOAD, IBS_OP_STORE, IBS_OP_BRANCH, memwithStrings, HEADER_SIZE, HPA_SIZE, EVENT_SIZE, IBS_REC_EVENT, IBS_REC_HPA

IBS_PREFIX = str("./ibs_")
IBS_SUFFIX = ".csv"


LOG_DIR = Path("/home/avezzu/ibs-cpu-fuzzer/logs/ibs_findings")

DEVICE_NAME = "/dev/svm_ibs_dev"
MAX_INSN_LENGTH = 15

#trace is dependent on CPU
TRACE_PATH = "/sys/kernel/debug/ibs_logger/trace2"
POLL_SLEEP_SEC = 0.05

FUZZ_IOC_GET_STATE = _IOR(ord('a'), ord('c'), FuzzerState)  
FUZZ_IOC_SET_STATE = _IOW(ord('a'), ord('d'), FuzzerState)  
FUZZ_IOC_OPEN_LOG = _IO(ord('a'), ord('e'))
FUZZ_IOC_CLOSE_LOG = _IO(ord('a'), ord('f'))
FUZZ_IOC_MOVE_NEXT_INSTR = _IO(ord('a'), ord('g'))
FUZZ_IOC_SET_REGISTER_VALUE = _IOW(ord('a'), ord('h'), ctypes.c_uint64)


def generate_filename(insn_bytes: bytes) -> str:
    encoded = "".join(f"\\x{b:02x}" for b in insn_bytes)
    return f"{IBS_PREFIX}{encoded}{IBS_SUFFIX}"


def op_type_to_str(op_type: int) -> str:
    if op_type == IBS_OP_LOAD:
        return "load"
    if op_type == IBS_OP_STORE:
        return "store"
    if op_type == IBS_OP_BRANCH:
        return "branch"
    return "unknown"


def read_exact_or_none(f, n: int) -> bytes | None:
    chunks = []
    total = 0

    while total < n:
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


last_was_hpa = False
def handle_hpa_record(rec: IbsHpaRecord, out) -> None:
    global last_was_hpa
    out.write(f"HPA: 0x{rec.hpa:016x}\n")
    last_was_hpa = True

def handle_event_record(rec: IbsEventRecord, out) -> None:
    global last_was_hpa
    if last_was_hpa:
        out.write(",".join([
            "rip","uop_cnt","phys_addr","lin_addr","branch_target_rip",
            "rax","rbx","rcx","rdx","rsi","rdi","r8","r9","r10","r11",
            "r12","r13","r14","r15","rsp","rbp","rflags","op_type",
            "mem_width","dc_uc_mem_acc","dc_wc_mem_acc","dc_miss",
            "op_microcode","op_brn_fuse","op_brn_ret","op_brn_misp",
            "op_brn_taken",
        ]) + "\n")

    out.write(",".join([
        f"0x{rec.rip:x}",
        str(rec.uop_cnt),
        f"0x{rec.phys_addr:x}",
        f"0x{rec.lin_addr:x}",
        f"0x{rec.branch_target_rip:x}",
        f"0x{rec.rax:x}",
        f"0x{rec.rbx:x}",
        f"0x{rec.rcx:x}",
        f"0x{rec.rdx:x}",
        f"0x{rec.rsi:x}",
        f"0x{rec.rdi:x}",
        f"0x{rec.r8:x}",
        f"0x{rec.r9:x}",
        f"0x{rec.r10:x}",
        f"0x{rec.r11:x}",
        f"0x{rec.r12:x}",
        f"0x{rec.r13:x}",
        f"0x{rec.r14:x}",
        f"0x{rec.r15:x}",
        f"0x{rec.rsp:x}",
        f"0x{rec.rbp:x}",
        f"0x{rec.rflags:x}",
        op_type_to_str(rec.op_type),
        memwithStrings[rec.mem_width],
        str(rec.dc_uc_mem_acc),
        str(rec.dc_wc_mem_acc),
        str(rec.dc_miss),
        str(rec.op_microcode),
        str(rec.op_brn_fuse),
        str(rec.op_brn_ret),
        str(rec.op_brn_misp),
        str(rec.op_brn_taken),
    ]) + "\n")

    last_was_hpa = False

def open_device() -> int:
    fd = os.open(DEVICE_NAME, os.O_RDWR)
    return fd

def ioctl_set_state(fd: int, st: FuzzerState) -> None:
    rc = _ioctl(fd, FUZZ_IOC_SET_STATE, ctypes.byref(st))
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(SET_STATE) failed: {os.strerror(e)}")
    
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
    
def ioctl_set_register_value(fd: int, value: int) -> None:
    rc = _ioctl(fd, FUZZ_IOC_SET_REGISTER_VALUE, ctypes.byref(ctypes.c_uint64(value)))
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(SET_REGISTER_VALUE) failed: {os.strerror(e)}")

def set_instruction(instr : bytes, instr_len : int) -> FuzzerState:
    st = FuzzerState()

    st.total_range.start.len = 0
    st.total_range.end.len = 0
    for i in range(MAX_INSN_LENGTH):
        st.total_range.start.bytes[i] = 0x00
        st.total_range.end.bytes[i] = 0xFF

    st.total_range.started = True
    for i in range(instr_len):
        st.inj.i.bytes[i] = instr[i]

    st.inj.i.len = instr_len
    st.inj.index = 0
    st.inj.last_len = 0

    st.current_op = INSTRUCTION
    st.fetch_counter = 0
    st.per_instruction_counter = 0
    st.file_open = False

    return st

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



def trace_loop(
    device_fd: int,
    qemu_proc: subprocess.Popen,
) -> int:
    ioctl_close_log(device_fd)  
    ioctl_open_log(device_fd)

    relay_fd = open(TRACE_PATH, "rb", buffering=0)
    current_insn_bytes = None
    out = None
    current_path = None

    try:
        while True:
            
            header_blob = read_exact_or_none(relay_fd, HEADER_SIZE)
            if header_blob is None:
                time.sleep(POLL_SLEEP_SEC)
                continue
            
            hdr = IbsRecordHeader.from_buffer_copy(header_blob)
            if hdr.record_len < HEADER_SIZE:
                print(f"WARN: malformed record with len={hdr.record_len}, skipping", file=sys.stderr)
                continue
            
            if current_insn_bytes == None:
                current_insn_bytes = bytes(hdr.instruction[:hdr.instruction_len])
                current_path = generate_filename(current_insn_bytes)
                out = open(current_path, "w", buffering=1)
            elif current_insn_bytes != bytes(hdr.instruction[:hdr.instruction_len]):
                if out is not None:
                    out.close()
                    relay_fd.close()
                    kill_qemu(qemu_proc)
                    print(f"Saved trace for instruction: {current_insn_bytes.hex()} at {current_path}", file=sys.stderr)
                    return 0
                

            remaining = hdr.record_len - HEADER_SIZE
            body_blob = read_exact_or_none(relay_fd, remaining)
            if body_blob is None:
                time.sleep(POLL_SLEEP_SEC)
                continue

            full_blob = header_blob + body_blob

            if hdr.record_type == IBS_REC_HPA:
                if hdr.record_len != HPA_SIZE:
                    print(f"WARN: malformed HPA record with len={hdr.record_len}, skipping", file=sys.stderr)
                    continue
                rec = IbsHpaRecord.from_buffer_copy(full_blob)
                handle_hpa_record(rec, out)

            elif hdr.record_type == IBS_REC_EVENT:
                if hdr.record_len != EVENT_SIZE:
                    raise ValueError(
                        f"EVENT record size mismatch: got {hdr.record_len}, expected {EVENT_SIZE}"
                    )
                rec = IbsEventRecord.from_buffer_copy(full_blob)
                handle_event_record(rec, out)

            else:
                print(f"WARN: unknown record type {hdr.record_type}, skipping", file=sys.stderr)
                continue
    
    except KeyboardInterrupt:
        if qemu_proc is not None:
            print("Stopping QEMU ...", file=sys.stderr)
            kill_qemu(qemu_proc)
            relay_fd.close()


def extract_bytes(source_file: str) -> bytes:
    hex_bytes = re.findall(r'\\x([0-9a-fA-F]{2})', source_file)
    return bytes(int(b, 16) for b in hex_bytes)


def main() -> int:

    try:
        dev_fd = open_device()
    except OSError as e:
        print(f"Failed to open {DEVICE_NAME}: {e}", file=sys.stderr)
        return 1

    
    it = LOG_DIR.iterdir()
    
    # Find the first subdirectory
    first_subdir = None
    for item in it:
        if item.is_dir() and len(list(item.glob("*.json"))) > 0:
            first_subdir = item
            break
    
    if first_subdir is None:
        print(f"No subdirectories found in {LOG_DIR}", file=sys.stderr)
        os.close(dev_fd)
        return 1
    
    # Get the first log file from the subdirectory
    iter = first_subdir.iterdir()
    for _ in range(1):
        first_file = next(iter)


    print(f"Using log file: {first_file}", file=sys.stderr)
    with first_file.open() as f:
        data = json.load(f) 

    instr = extract_bytes(data["source_file"])
    st = set_instruction(instr, len(instr))
    ioctl_set_state(dev_fd, st)
    ioctl_set_register_value(dev_fd, 0x00005480000000)
    qemu_script = Path("./../vms/qemu.sh")

    try:
        qemu_proc = start_qemu(parse_qemu_script(qemu_script))
        print(f"Started QEMU via {qemu_script} (pid={qemu_proc.pid})", file=sys.stderr)
    except Exception as e:
        print(f"Failed to start QEMU: {e}", file=sys.stderr)
        os.close(dev_fd)
        return 1
    

    rc = trace_loop(dev_fd, qemu_proc)
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

    try:
        subprocess.run(
            ["sudo", "killall", "qemu-system-x86_64"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )
    except Exception as e:
        print(f"Warning: failed to kill existing qemu instances: {e}", file=sys.stderr)

    os.sched_setaffinity(0, {2})
    sys.exit(main())