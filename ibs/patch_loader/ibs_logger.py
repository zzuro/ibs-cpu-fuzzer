#!/usr/bin/env python3

from relayfs import *

import argparse
import errno
import os
import sys
import time
from pathlib import Path


LOG_DIR = Path("/home/avezzu/ibs-cpu-fuzzer-dev/ibs")
IBS_PREFIX = str(LOG_DIR / "ibs_")
IBS_SUFFIX = ".csv"

# Kernel module runs on core 8, so relayfs/debugfs file should be trace8.
TRACE_PATH = "/sys/kernel/debug/ibs_logger/trace8"

POLL_SLEEP_SEC = 0.05
WAIT_LOG_SLEEP_SEC = 0.1


def create_log_directory():
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def reset_log_directory():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    for f in LOG_DIR.iterdir():
        if f.is_file() and f.name.startswith("ibs_") and f.name.endswith(IBS_SUFFIX):
            f.unlink()


def wait_for_trace_path(trace_path: str) -> None:
    print(f"Waiting for relayfs trace file: {trace_path}", file=sys.stderr)

    while not os.path.exists(trace_path):
        time.sleep(WAIT_LOG_SLEEP_SEC)

    print(f"Found relayfs trace file: {trace_path}", file=sys.stderr)


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


def write_csv_header(out) -> None:
    out.write(",".join([
        "rip",
        "uop_cnt",
        "phys_addr",
        "lin_addr",
        "op_type",
        "mem_width",
        "dc_uc_mem_acc",
        "dc_wc_mem_acc",
        "dc_miss",
    ]) + "\n")


def handle_event_record(rec: IbsEventRecord, out) -> None:
    if out is None:
        return

    try:
        mem_width = memwithStrings[rec.mem_width]
    except Exception:
        mem_width = f"unknown({rec.mem_width})"

    out.write(",".join([
        f"0x{rec.rip:x}",
        str(rec.uop_cnt),
        f"0x{rec.phys_addr:x}",
        f"0x{rec.lin_addr:x}",
        op_type_to_str(rec.op_type),
        mem_width,
        str(rec.dc_uc_mem_acc),
        str(rec.dc_wc_mem_acc),
        str(rec.dc_miss),
    ]) + "\n")


def trace_loop(trace_path: str) -> int:
    create_log_directory()
    wait_for_trace_path(trace_path)

    print(f"Reading relayfs trace from: {trace_path}", file=sys.stderr)
    print(f"Writing decoded logs to:    {LOG_DIR}", file=sys.stderr)

    relay_fd = open(trace_path, "rb", buffering=0)

    current_insn_bytes = None
    out = None
    wrote_header_for_file = False

    try:
        while True:
            header_blob = read_exact_or_none(relay_fd, HEADER_SIZE)
            if header_blob is None:
                time.sleep(POLL_SLEEP_SEC)
                continue

            hdr = IbsRecordHeader.from_buffer_copy(header_blob)

            if hdr.record_len < HEADER_SIZE:
                print(
                    f"WARN: malformed record, len={hdr.record_len}, skipping",
                    file=sys.stderr,
                )
                continue

            remaining = hdr.record_len - HEADER_SIZE
            body_blob = read_exact_or_none(relay_fd, remaining)
            if body_blob is None:
                time.sleep(POLL_SLEEP_SEC)
                continue

            full_blob = header_blob + body_blob

            if hdr.record_type == IBS_REC_FINISH:
                print("Received FINISH record, stopping.", file=sys.stderr)
                break

            insn_len = int(hdr.instruction_len)
            insn_bytes = bytes(hdr.instruction[:insn_len])

            if current_insn_bytes != insn_bytes:
                current_insn_bytes = insn_bytes
                current_path = generate_filename(current_insn_bytes)

                if out is not None:
                    out.close()

                out = open(current_path, "w", buffering=1)
                wrote_header_for_file = False

                print(
                    f"Now logging instruction {insn_bytes.hex()} -> {current_path}",
                    file=sys.stderr,
                )

            if hdr.record_type == IBS_REC_EVENT:
                if hdr.record_len != EVENT_SIZE:
                    print(
                        f"WARN: malformed EVENT record, len={hdr.record_len}, expected={EVENT_SIZE}",
                        file=sys.stderr,
                    )
                    continue

                if out is not None and not wrote_header_for_file:
                    write_csv_header(out)
                    wrote_header_for_file = True

                rec = IbsEventRecord.from_buffer_copy(full_blob)
                handle_event_record(rec, out)

            else:
                print(
                    f"WARN: unknown record type {hdr.record_type}, skipping",
                    file=sys.stderr,
                )
                continue

    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr)

    finally:
        if out is not None:
            out.close()

        relay_fd.close()

    return 0


def main() -> int:
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--trace-path",
        default=TRACE_PATH,
        help="relayfs/debugfs trace file to read, default: /sys/kernel/debug/ibs_logger/trace8",
    )

    ap.add_argument(
        "--reset",
        action="store_true",
        help="delete existing ibs_*.csv files in output directory before starting",
    )

    args = ap.parse_args()

    if args.reset:
        reset_log_directory()
    else:
        create_log_directory()

    return trace_loop(args.trace_path)


if __name__ == "__main__":
    os.sched_setaffinity(0, {8})
    raise SystemExit(main())