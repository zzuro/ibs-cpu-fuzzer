import csv
import re
from pathlib import Path
from tqdm import tqdm

HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
HPA_RE = re.compile(r"^HPA:\s*(0x[0-9a-fA-F]+)\s*$")
BOOLISH = {"0", "1", "True", "False"}

EXPECTED_HEADER = [
    "rip","uop_cnt","phys_addr","lin_addr","branch_target_rip",
    "rax","rbx","rcx","rdx","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15",
    "rsp","rbp","rflags",
    "op_type","mem_width",
    "dc_uc_mem_acc","dc_wc_mem_acc","dc_miss",
    "op_microcode","op_brn_fuse","op_brn_ret",
    "op_brn_misp","op_brn_taken",
]

HEX_COLUMNS = {
    "rip","phys_addr","lin_addr","branch_target_rip",
    "rax","rbx","rcx","rdx","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15",
    "rsp","rbp","rflags",
}

INT_COLUMNS = {"uop_cnt"}

FLAG_COLUMNS = {
    "dc_uc_mem_acc","dc_wc_mem_acc","dc_miss",
    "op_microcode","op_brn_fuse","op_brn_ret",
    "op_brn_misp","op_brn_taken",
}


def is_hex(val):
    return bool(HEX_RE.fullmatch(val))


def is_int(val):
    return val.isdigit()


def is_boolish(val):
    return val in BOOLISH


def print_row(header, row):
    pairs = [f"{h}: {v}" for h, v in zip(header, row)]
    print(", ".join(pairs))


def error(path, msg):
    print(f"[ERROR] {path} - {msg}")


def check_csv(path):
    with open(path, newline="") as f:

        for i in range(512):
            line = f.readline()
            if not line:
                error(path, "file ended before 512 HPA lines")
                return

            line = line.rstrip("\n")

            if not HPA_RE.fullmatch(line):
                error(path, f"line {i+1}: invalid HPA line -> {line}")
                return

        reader = csv.reader(f)

        try:
            header = next(reader)
        except StopIteration:
            error(path, "missing CSV header")
            return

        if header != EXPECTED_HEADER:
            error(path, "CSV header mismatch")
            print("Expected:", ",".join(EXPECTED_HEADER))
            print("Got     :", ",".join(header))
            return

        num_cols = len(header)

        for line_no, row in enumerate(reader, start=514):

            if len(row) != num_cols:
                error(path, f"line {line_no}: wrong column count (expected {num_cols}, got {len(row)})")
                print_row(header, row)
                return

            row_dict = dict(zip(header, row))

            for col in HEX_COLUMNS:
                if not is_hex(row_dict[col]):
                    error(path, f"line {line_no}: {col} not hex -> {row_dict[col]}")
                    return

            for col in INT_COLUMNS:
                if not is_int(row_dict[col]):
                    error(path, f"line {line_no}: {col} not int -> {row_dict[col]}")
                    return

            for col in FLAG_COLUMNS:
                if not is_boolish(row_dict[col]):
                    error(path, f"line {line_no}: {col} invalid flag -> {row_dict[col]}")
                    return

            if not row_dict["op_type"]:
                error(path, f"line {line_no}: op_type empty")
                return

            if not row_dict["mem_width"]:
                error(path, f"line {line_no}: mem_width empty")
                return

if __name__ == "__main__":

    log_dir = Path("/mnt/ibs_log")

    files = [f for f in sorted(log_dir.glob("*")) if f.is_file()]

    for file in tqdm(files, desc="Validating IBS logs"):
        check_csv(file)

    print("\nDone.")
    print("If no errors were reported, all files are valid.")