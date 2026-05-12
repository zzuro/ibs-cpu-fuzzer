#!/usr/bin/env python3

import argparse
import re
from collections import defaultdict


CACHELINE_SIZE = 64


MAPPING_LINE_RE = re.compile(
    r"""
    ^(?:\[\s*[0-9]+\.[0-9]+\]\s*)?
    \[RIP:\s*0x[0-9a-fA-F]+\]
    \[uop\s+cnt:\s*[0-9]+\]
    \s*
    \[\s*(?P<op>load32|store32)\s*\]
    \s+
    (?P<paddr>0x[0-9a-fA-F]+)
    \s+
    \(v=(?P<vaddr>0x[0-9a-fA-F]+)\)
    """,
    re.VERBOSE,
)


ACCESS_LINE_RE = re.compile(
    r"""
    \[\s*(?P<op>load\d+|store\d+)\s*\]
    \s+
    (?P<paddr>0x[0-9a-fA-F]+)
    \s+
    \(v=(?P<vaddr>0x[0-9a-fA-F]+)\)
    .*?
    CacheMiss\s*\[\s*(?P<cachemiss>[+-])\s*\]
    """,
    re.VERBOSE,
)


def cacheline_base(addr: int) -> int:
    return addr & ~(CACHELINE_SIZE - 1)


def build_load_to_store_mapping(mapping_log_path: str):
    pairs = []
    pending_load_vaddr = None

    with open(mapping_log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = MAPPING_LINE_RE.search(line)
            if not m:
                continue

            op = m.group("op")
            paddr = m.group("paddr").lower()
            vaddr = m.group("vaddr").lower()

            if op == "load32":
                pending_load_vaddr = vaddr

            elif op == "store32" and pending_load_vaddr is not None:
                pairs.append((pending_load_vaddr, paddr))
                pending_load_vaddr = None

    return pairs


def build_cacheline_stats(access_log_path: str):
    stats = defaultdict(lambda: {
        "accesses": 0,
        "hits": 0,
        "misses": 0,
        "loads": 0,
        "stores": 0,
    })

    with open(access_log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = ACCESS_LINE_RE.search(line)
            if not m:
                continue

            op = m.group("op")
            paddr = int(m.group("paddr"), 16)
            cachemiss = m.group("cachemiss")

            cl = cacheline_base(paddr)

            stats[cl]["accesses"] += 1

            if cachemiss == "+":
                stats[cl]["misses"] += 1
            else:
                stats[cl]["hits"] += 1

            if op.startswith("load"):
                stats[cl]["loads"] += 1
            elif op.startswith("store"):
                stats[cl]["stores"] += 1

    return stats


def write_output(pairs, stats, output_path: str):
    with open(output_path, "w", encoding="utf-8") as out:
        out.write(
            "load_vaddr             -> store_paddr           "
            "cacheline              accesses      hits    misses    loads   stores\n"
        )

        for load_vaddr, store_paddr in pairs:
            store_addr_int = int(store_paddr, 16)
            cl = cacheline_base(store_addr_int)
            s = stats.get(cl, {
                "accesses": 0,
                "hits": 0,
                "misses": 0,
                "loads": 0,
                "stores": 0,
            })

            out.write(
                f"{load_vaddr:<22} -> {store_paddr:<20} "
                f"0x{cl:016x} "
                f"{s['accesses']:8d} "
                f"{s['hits']:9d} "
                f"{s['misses']:9d} "
                f"{s['loads']:8d} "
                f"{s['stores']:8d}\n"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Create load32-vaddr -> store32-paddr mapping and add cacheline hit/miss stats."
    )

    parser.add_argument(
        "mapping_log",
        help="Log used to derive load32 virtual address -> following store32 physical address mapping",
    )

    parser.add_argument(
        "access_log",
        help="Log used to compute cacheline access/hit/miss statistics",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="mapping_with_cacheline_stats.txt",
        help="Output file",
    )

    args = parser.parse_args()

    pairs = build_load_to_store_mapping(args.mapping_log)
    stats = build_cacheline_stats(args.access_log)
    write_output(pairs, stats, args.output)


if __name__ == "__main__":
    main()