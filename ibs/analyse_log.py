#!/usr/bin/env python3

import argparse
import re
from collections import defaultdict


CACHELINE_SIZE = 64

LINE_RE = re.compile(
    r"""
    ^\[RIP:\s*(?P<rip>0x[0-9a-fA-F]+)\]
    \[uop\s+cnt:\s*(?P<uopcnt>[0-9]+)\]
    \s*
    \[\s*(?P<op>[^\]]+?)\s*\]
    (?:
        \s+
        (?P<paddr>0x[0-9a-fA-F]+)
        \s+
        \(v=(?P<vaddr>0x[0-9a-fA-F]+)\)
    )?
    .*?
    CacheMiss\s*\[\s*(?P<cachemiss>[+-])\s*\]
    """,
    re.VERBOSE,
)


def cacheline_base(addr: int) -> int:
    return addr & ~(CACHELINE_SIZE - 1)


def parse_log(input_path: str, filtered_output_path: str, addr_prefix: str):
    stats = defaultdict(lambda: {
        "total": 0,
        "hits": 0,
        "misses": 0,
        "loads": 0,
        "stores": 0,
    })

    total_lines = 0
    parsed_lines = 0
    kept_non_alu_lines = 0
    matching_mem_ops = 0
    unparsed_lines = 0

    addr_prefix = addr_prefix.lower()

    with open(input_path, "r", encoding="utf-8", errors="replace") as infile, \
         open(filtered_output_path, "w", encoding="utf-8") as filtered_out:

        for line in infile:
            total_lines += 1

            m = LINE_RE.search(line)
            if not m:
                unparsed_lines += 1
                continue

            parsed_lines += 1

            op = m.group("op").strip()

            if op == "ALU":
                continue

            filtered_out.write(line)
            kept_non_alu_lines += 1

            paddr_str = m.group("paddr")
            if not paddr_str:
                continue

            if not paddr_str.lower().startswith(addr_prefix):
                continue

            paddr = int(paddr_str, 16)
            cl = cacheline_base(paddr)

            cachemiss = m.group("cachemiss")

            stats[cl]["total"] += 1
            matching_mem_ops += 1

            if cachemiss == "+":
                stats[cl]["misses"] += 1
            else:
                stats[cl]["hits"] += 1

            if op.startswith("load"):
                stats[cl]["loads"] += 1
            elif op.startswith("store"):
                stats[cl]["stores"] += 1

    return {
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "unparsed_lines": unparsed_lines,
        "kept_non_alu_lines": kept_non_alu_lines,
        "matching_mem_ops": matching_mem_ops,
        "stats": stats,
    }


def write_stats(result, stats_output_path: str):
    stats = result["stats"]

    with open(stats_output_path, "w", encoding="utf-8") as f:
        f.write("=== Summary ===\n")
        f.write(f"Total input lines:              {result['total_lines']}\n")
        f.write(f"Parsed lines:                   {result['parsed_lines']}\n")
        f.write(f"Unparsed lines:                 {result['unparsed_lines']}\n")
        f.write(f"Non-ALU lines written:          {result['kept_non_alu_lines']}\n")
        f.write(f"Matching memory operations:     {result['matching_mem_ops']}\n")
        f.write(f"Distinct cache lines:           {len(stats)}\n")
        f.write("\n")

        f.write("=== Per-cache-line statistics ===\n")
        f.write(
            f"{'cacheline_base':>20}  "
            f"{'total':>8}  "
            f"{'loads':>8}  "
            f"{'stores':>8}  "
            f"{'hits':>8}  "
            f"{'misses':>8}  "
            f"{'miss_rate':>10}\n"
        )

        for cl, s in sorted(stats.items()):
            total = s["total"]
            hits = s["hits"]
            misses = s["misses"]
            loads = s["loads"]
            stores = s["stores"]
            miss_rate = misses / total if total else 0.0

            f.write(
                f"0x{cl:016x}  "
                f"{total:8d}  "
                f"{loads:8d}  "
                f"{stores:8d}  "
                f"{hits:8d}  "
                f"{misses:8d}  "
                f"{miss_rate:9.2%}\n"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Filter log to non-ALU lines and write cacheline-level physical-address statistics to a file."
    )

    parser.add_argument(
        "input",
        help="Input log file",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="filtered_non_alu.log",
        help="Output file containing only non-ALU lines",
    )

    parser.add_argument(
        "-s",
        "--stats-output",
        default="cacheline_stats.txt",
        help="Output file for cacheline statistics",
    )

    parser.add_argument(
        "--prefix",
        default="0x000ffffdf",
        help="Physical address prefix to include in statistics",
    )

    args = parser.parse_args()

    result = parse_log(args.input, args.output, args.prefix)
    write_stats(result, args.stats_output)


if __name__ == "__main__":
    main()