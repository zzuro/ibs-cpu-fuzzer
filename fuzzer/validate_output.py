import csv
import re

HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
HPA_RE = re.compile(r"^HPA:\s*(0x[0-9a-fA-F]+)\s*$")
BOOLISH = {"0", "1", "True", "False"}

EXPECTED_HEADER = [
    "rip",
    "uop_cnt",
    "phys_addr",
    "lin_addr",
    "branch_target_rip",
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rsp",
    "rbp",
    "rflags",
    "op_type",
    "mem_width",
    "dc_uc_mem_acc",
    "dc_wc_mem_acc",
    "dc_miss",
    "op_microcode",
    "op_brn_fuse",
    "op_brn_ret",
    "op_brn_misp",
    "op_brn_taken",
]

HEX_COLUMNS = {
    "rip",
    "phys_addr",
    "lin_addr",
    "branch_target_rip",
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rsp",
    "rbp",
    "rflags",
}

INT_COLUMNS = {
    "uop_cnt",
}

FLAG_COLUMNS = {
    "dc_uc_mem_acc",
    "dc_wc_mem_acc",
    "dc_miss",
    "op_microcode",
    "op_brn_fuse",
    "op_brn_ret",
    "op_brn_misp",
    "op_brn_taken",
}


def is_hex(val: str) -> bool:
    return bool(HEX_RE.fullmatch(val))


def is_int(val: str) -> bool:
    return val.isdigit()


def is_boolish(val: str) -> bool:
    return val in BOOLISH


def print_row(header, row):
    pairs = [f"{h}: {v}" for h, v in zip(header, row)]
    print(", ".join(pairs))


def check_csv(path):
    with open(path, newline="") as f:
        # Validate first 512 HPA lines
        for i in range(512):
            line = f.readline()
            if not line:
                print(f"[ERROR] File ended before 512 HPA lines (stopped at line {i + 1})")
                return

            line = line.rstrip("\n")
            m = HPA_RE.fullmatch(line)
            if not m:
                print(f"[ERROR] Line {i + 1}: invalid HPA line")
                print(f'Expected format: "HPA: 0x000000032bc09000"')
                print(f"Got: {line}")
                return

        reader = csv.reader(f)

        try:
            header = next(reader)
        except StopIteration:
            print("[ERROR] Missing CSV header after 512 HPA lines")
            return

        if header != EXPECTED_HEADER:
            print("[ERROR] CSV header does not match expected format")
            print(f"Expected ({len(EXPECTED_HEADER)} columns):")
            print(",".join(EXPECTED_HEADER))
            print(f"Got ({len(header)} columns):")
            print(",".join(header))
            return

        num_cols = len(header)
        print(f"Header columns: {num_cols}")

        for line_no, row in enumerate(reader, start=514):
            if len(row) != num_cols:
                print(f"[ERROR] Line {line_no}: wrong column count")
                print(f"Expected {num_cols} columns, got {len(row)}")
                print_row(header, row)
                return

            row_dict = dict(zip(header, row))

            for col in HEX_COLUMNS:
                if not is_hex(row_dict[col]):
                    print(f"[ERROR] Line {line_no}: {col} not hex")
                    print_row(header, row)
                    return

            for col in INT_COLUMNS:
                if not is_int(row_dict[col]):
                    print(f"[ERROR] Line {line_no}: {col} not integer")
                    print_row(header, row)
                    return

            for col in FLAG_COLUMNS:
                if not is_boolish(row_dict[col]):
                    print(f"[ERROR] Line {line_no}: {col} not 0/1/True/False")
                    print_row(header, row)
                    return

            if not row_dict["op_type"]:
                print(f"[ERROR] Line {line_no}: op_type is empty")
                print_row(header, row)
                return

            if not row_dict["mem_width"]:
                print(f"[ERROR] Line {line_no}: mem_width is empty")
                print_row(header, row)
                return

        print("CSV format looks good!")


if __name__ == "__main__":
    path = "/mnt/home/avezzu/ibs_log/ibs_\\x00\\x00.csv"
    check_csv(path)