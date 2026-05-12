# TSA: Transient Scheduler Attacks on Zen 4

This project provides the first public PoC for investigating TSA.

## Project Components

- **`tsa.c`**: An extraction kernel module that executes in Ring-0, pinned to a specific core. It uses direct CR3/PML5 manipulation to install virtual-to-physical mappings and leaks a secret using TSA.
- **`tsa_scanning.c`**: A scanner kernel module for finding affected PMCs.
- **`python_extractor.py`**: A post-processing script that parses kernel logs (`dmesg`) to identify "Golden Candidates"—architectural PMC signals where timing gaps indicate potential TSA side effects.
- **`find_microtags.c`**: A user-space utility for measuring pointer-chasing latency and identifying microarchitectural utag bits.

## Prerequisites

- Linux Kernel Headers (matching your running kernel)
- `gcc` and `make`
- Root privileges (for inserting/removing kernel modules)
- Python 3 (for the analysis script)

## Compilation

### 1. Kernel Modules
To compile the `tsa` and `tsa_scanning` modules:
```bash
make
```

### 2. User-space Utility
To compile the `find_microtags` utility:
```bash
gcc find_microtags.c -o find_microtags
```

## Usage

### Running the Extractor
The extractor clears the kernel ring buffer, inserts the module, waits for execution to complete, and then displays the results:
```bash
sudo make insmod
```

### Running the Scanner
Similarly, to run the scanner module:
```bash
sudo make insmod-scan
```

### Analyzing Results
While running the extractor or scanner, you can save the kernel log and analyze it with the Python script:
```bash
sudo dmesg -w > dmesg_mul_cachelin.log
python3 python_extractor.py
```

### Cleanup
To remove the modules and clean the build directory:
```bash
sudo make rmmod-ext
sudo make rmmod-scan
make clean
```

## Microarchitectural Context
This research targets the Zen 4 pipeline behavior during TSA. By monitoring specific performance counters (e.g., `MSR_ZEN4_PERF_CTL0`), the tools leaks same address space data using TSA.
