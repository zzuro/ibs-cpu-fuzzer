#!/usr/bin/env python3

import sys
import ctypes
from pathlib import Path

from relayfs import *
from fuzz_state import *

LOG_DIR = Path("/mnt/ssd/ibs_log")

HEADER_SIZE = ctypes.sizeof(IbsRecordHeader)
HPA_SIZE = ctypes.sizeof(IbsHpaRecord)
EVENT_SIZE = ctypes.sizeof(IbsEventRecord)


def op_type_to_str(op_type: int) -> str:
    if op_type == IBS_OP_LOAD:
        return "load"
    if op_type == IBS_OP_STORE:
        return "store"
    if op_type == IBS_OP_BRANCH:
        return "branch"
    return "unknown"


def read_exact(f, n: int):
    data = f.read(n)
    if len(data) != n:
        return None
    return data


def convert_file(bin_path: Path) -> None:
    csv_path = Path("/home/avezzu/ibs-cpu-fuzzer/analysis") / bin_path.name.replace(".bin", ".csv")
    last_was_hpa = False

    with open(bin_path, "rb") as f, open(csv_path, "w", buffering=1) as out:
        while True:
            header_blob = read_exact(f, HEADER_SIZE)
            if header_blob is None:
                break

            hdr = IbsRecordHeader.from_buffer_copy(header_blob)

            if hdr.record_len < HEADER_SIZE:
                break

            body_blob = read_exact(f, hdr.record_len - HEADER_SIZE)
            if body_blob is None:
                break

            full_blob = header_blob + body_blob

            if hdr.record_type == IBS_REC_HPA:
                if hdr.record_len != HPA_SIZE:
                    continue

                rec = IbsHpaRecord.from_buffer_copy(full_blob)
                out.write(f"HPA: 0x{rec.hpa:016x}\n")
                last_was_hpa = True

            elif hdr.record_type == IBS_REC_EVENT:
                if hdr.record_len != EVENT_SIZE:
                    continue

                rec = IbsEventRecord.from_buffer_copy(full_blob)

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


def main() -> int:
    if not LOG_DIR.exists():
        print(f"directory not found: {LOG_DIR}", file=sys.stderr)
        return 1

    # files = sorted(LOG_DIR.glob("*.bin"))
    # print(f"Found {len(files)} binary trace files in {LOG_DIR}")

    files = [Path("/mnt/ssd/ibs_log/ibs_\\x0b\\x04\\x9d\\xf4\\x00\\x00\\x00.bin")]
    for bin_path in files:
        if "snap" in bin_path.name:
            continue
        print(f"Converting {bin_path.name} -> {bin_path.with_suffix('.csv')}")
        try:
            convert_file(bin_path)
        except Exception as e:
            print(f"Failed to convert {bin_path}: {e}", file=sys.stderr)

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())