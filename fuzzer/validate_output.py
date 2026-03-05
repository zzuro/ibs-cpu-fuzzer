import csv
import re

HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
BOOLS = {"True", "False"}

def is_hex(val):
    return bool(HEX_RE.match(val))

def print_row(header, row):
    pairs = [f"{h}: {v}" for h, v in zip(header, row)]
    print(", ".join(pairs))

def check_csv(path):

    with open(path, newline="") as f:
        reader = csv.reader(f)

        for _ in range(512):
            next(reader)

        header = next(reader)
        num_cols = len(header)
        print(f"Header columns: {num_cols}")

        #first 512 lines are HPA of VM
        for line_no, row in enumerate(reader, start=2 + 512):

            if len(row) != num_cols:
                print(f"[ERROR] Line {line_no}: wrong column count")
                print(f"Expected {num_cols} columns, got {len(row)}")
                print_row(header, row)
                return

            if not is_hex(row[0]):
                print(f"[ERROR] Line {line_no}: RIP not hex")
                print_row(header, row)
                return

            if not row[1].isdigit():
                print(f"[ERROR] Line {line_no}: UOP_CNT not integer")
                print_row(header, row)
                return

            for idx in [5,6,7,8,9,10,11,12]:
                if row[idx] not in BOOLS:
                    print(f"[ERROR] Line {line_no}: {header[idx]} not bool")
                    print_row(header, row)
                    return

        print("CSV format looks good!")

if __name__ == "__main__":
    path = "/mnt/home/avezzu/ibs_log/ibs_\\x00\\x00.csv"
    check_csv(path)