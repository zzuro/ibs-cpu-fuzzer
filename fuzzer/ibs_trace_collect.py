#!/usr/bin/env python3
import os
import re
import sys
import shutil
from pathlib import Path

TRACEFS = Path("/sys/kernel/tracing")
TRACE_PIPE = TRACEFS / "trace_pipe"

EVENT_DIR = TRACEFS / "events" / "ibs"
ENABLE_MARKER = EVENT_DIR / "ibs_marker" / "enable"
ENABLE_EVENT  = EVENT_DIR / "ibs_event"  / "enable"

LOG_DIR = Path("/home/avezzu/ibs_log")
IBS_PREFIX = str(LOG_DIR / "ibs_")
IBS_SUFFIX = ".log"

MAX_INSN_LENGTH = 15

_HEXPAIR_RE = re.compile(r"([0-9a-fA-F]{2})")


def reset_log_directory():
    if LOG_DIR.exists():
        shutil.rmtree(LOG_DIR)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def enable_event(enable_path: Path) -> None:
    enable_path.write_text("1\n")


def parse_marker_bytes(line: str) -> bytes:
    i = line.find("bytes=")
    if i < 0:
        return b""
    tail = line[i + len("bytes="):]
    pairs = _HEXPAIR_RE.findall(tail)
    if not pairs:
        return b""
    b = bytes(int(p, 16) for p in pairs)
    return b[:MAX_INSN_LENGTH]


def generate_filename(insn_bytes: bytes) -> str:
    encoded = "".join(f"\\x{b:02x}" for b in insn_bytes)
    return f"{IBS_PREFIX}{encoded}{IBS_SUFFIX}"


def main() -> int:
    try:
        reset_log_directory()
    except Exception as e:
        print(f"Failed to reset log directory: {e}", file=sys.stderr)
        return 1


    try:
        enable_event(ENABLE_EVENT)
        enable_event(ENABLE_MARKER)
    except PermissionError:
        print("Need root (or permissions) to enable trace events.", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"Trace event path not found: {e}", file=sys.stderr)
        return 1

    try:
        f = open(TRACE_PIPE, "r", buffering=1)
    except PermissionError:
        print("Need root (or permissions) to read trace_pipe.", file=sys.stderr)
        return 1

    state = "WAIT_START"
    out = None
    current_path = None

    print(f"Reading {TRACE_PIPE} ...", file=sys.stdout)

    try:
        for line in f:
            line = line.rstrip("\n")

            is_marker = "ibs_marker:" in line
            is_event = "ibs_event:" in line

            if state == "WAIT_START":
                if is_marker and "START" in line:
                    insn = parse_marker_bytes(line)
                    if not insn:
                        print(f"WARN: START without parsable bytes: {line}", file=sys.stderr)
                        continue

                    current_path = generate_filename(insn)
                    out = open(current_path, "w", buffering=1)
                    state = "COLLECT_EVENTS"
                continue

            if state == "COLLECT_EVENTS":
                if is_event:
                    if out:
                        line = line.split("ibs_event:", 1)[1].strip()
                        out.write(line + "\n")
                elif is_marker and "FINISHED" in line:
                    if out:
                        out.close()
                    out = None
                    current_path = None
                    state = "WAIT_START"
                continue

    except KeyboardInterrupt:
        pass
    finally:
        if out:
            out.close()
        f.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())