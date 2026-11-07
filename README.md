> This repository was developed as part of my master's thesis at ETH Zurich: **Uncovering Microarchitectural Leakage on AMD Processors Through IBS-Guided Instruction Fuzzing**, by Alessandro Vezzù.
>
> **Thesis:** [Uncovering Microarchitectural Leakage on AMD Processors Through IBS-Guided Instruction Fuzzing](https://doi.org/10.3929/ethz-c-000809158)

# IBS CPU Fuzzer

A research framework for exploring x86 instruction behavior using AMD **Instruction-Based Sampling (IBS)**. It combines an instruction fuzzer integrated into KVM, a minimal guest kernel, per-CPU trace collection, and offline analysis of sampled micro-operations.

The IBS CPU fuzzer also led to the development of  **Skyfall** , which investigates transient data sampling across privileged execution paths, including AMD SEV-SNP, the microcode loader, and System Management Mode (SMM). This repository focuses on the fuzzing and IBS analysis infrastructure underlying the research and does not provide a complete reproduction package for all attacks and experiments presented in the thesis. The framework developed for **Skyfall** is available in the [Skyfall repository](https://github.com/skyfall-attack).

## How it works

```mermaid
flowchart LR
    G[Minimal COQUITO guest] <--> K[Modified Linux / KVM-SVM fuzzer]
    K --> I[IBS samples]
    I --> R[Per-CPU relay channels]
    R --> C[Python collector]
    C --> B[Binary instruction traces]
    B --> A[Rust analyzer]
    A --> F[JSON findings for manual inspection]
```

The fuzzer explores instruction encodings using Sandsifter-style tunneling and resolves instruction length through page-boundary faults. KVM restores guest state between trials. Instructions selected for tracing execute repeatedly with different initial register values, allowing the analysis to relate observed addresses and control flow to operands.

The thesis describes 6,000 executions per operand configuration and ten configurations per instruction. These are experimental parameters that may change with the code and platform. The thesis evaluates the instruction fuzzer on an AMD EPYC 9124 (Zen 4).

## Repository guide

| Path                                                                                                                | Contents and purpose                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`fuzzer/linux/`](fuzzer/linux/)                                                                                   | Full modified Linux 6.17 source tree, including the KVM/SVM instruction fuzzer and IBS logging. This is the host kernel for the main workflow.                |
| [`svm.c`](fuzzer/linux/arch/x86/kvm/svm/svm.c) and [`fuzzer.h`](fuzzer/linux/arch/x86/kvm/svm/fuzzer.h)           | Instruction generation, guest execution and state handling, and the `/dev/svm_ibs_dev` control interface.                                                   |
| [`ibs_logger.c`](fuzzer/linux/arch/x86/kvm/svm/ibs_logger.c)                                                       | IBS record production and per-CPU relay logging.                                                                                                              |
| [`fuzzer/ibs_trace_collect.py`](fuzzer/ibs_trace_collect.py)                                                       | Starts QEMU workers pinned to selected CPUs, collects binary traces, handles inactivity timeouts, and saves progress snapshots.                               |
| [`fuzzer/fuzz_state.py`](fuzzer/fuzz_state.py), [`relayfs.py`](fuzzer/relayfs.py), [`ioctl.py`](fuzzer/ioctl.py) | Python definitions for kernel state, binary records, and ioctl calls.                                                                                         |
| [`coquito/`](coquito/)                                                                                             | Minimal guest kernel, reset-vector bootloader, and firmware-image builder. The guest provides the execution environment and handshake with the modified host. |
| [`vms/qemu.sh`](vms/qemu.sh)                                                                                       | Single-vCPU QEMU/KVM launcher used by the collector. Boots the generated firmware without a disk image.                                                       |
| [`analysis/analyzer/`](analysis/analyzer/)                                                                         | Multithreaded Rust/Polars analyzer: binary traces to JSON findings, progress state, and failure logs.                                                         |
| [`analysis/tester.py`](analysis/tester.py)                                                                         | Focused instruction retesting through the same kernel interface, with CSV output.                                                                             |
| [`analysis/filter.py`](analysis/filter.py), [`filter.md`](analysis/filter.md)                                     | Experiment-specific JSON filtering and notes on interestingness indicators.                                                                                   |
| [`fuzzer/bin_to_csv.py`](fuzzer/bin_to_csv.py), [`validate_output.py`](fuzzer/validate_output.py)                 | Binary-to-CSV conversion and validation of the expected CSV layout.                                                                                           |
| [`ibs/`](ibs/)                                                                                                     | Standalone userspace IBS sampler, cache/store workloads, and separate kernel-level tracing experiments in `ibs/kernel/`.                                    |
| [`fuzzer/sandsifter/`](fuzzer/sandsifter/)                                                                         | Auxiliary instruction injector and guest program, separate from the main KVM-integrated workflow.                                                             |
| [`vms/qemu/`](vms/qemu/)                                                                                           | Additional VM setup scripts, including an Ubuntu cloud-image downloader and an SEV-SNP VM launcher.                                                           |
| [`mount.py`](mount.py)                                                                                             | Original lab-specific storage mounting helper. Adapt its hostnames, devices, and mount locations for another environment.                                     |

## Requirements

The main workflow runs on a **native x86-64 Linux host** with an AMD processor supporting IBS and SVM/KVM, with virtualization enabled in firmware. It requires root access, the modified kernel in this repository, and QEMU with KVM support. A stock Linux kernel does not provide this project's fuzzer device or relay channels.

Use a dedicated experimental machine: this code changes privileged virtualization paths and executes unusual instructions. Some experiments can hang or crash the host.

Build tools include GCC, GNU binutils, Make, NASM, Python 3.10 or newer, and the dependencies needed to build and package Linux. The guest image builder needs Python packages `click` and `pyelftools`. Offline analysis needs a Rust toolchain supporting edition 2024 and the dependencies pinned in `Cargo.lock`.

Commands below use Bash and start from the repository root unless stated otherwise. The checked-in scripts retain original experiment settings that must be adapted to your machine.

## Run the instruction fuzzer

### 1. Build the minimal guest

```bash
cd coquito
python3 -m venv .venv
.venv/bin/python -m pip install click pyelftools
bash build.sh
cd ..
```

This builds the reset vector and COQUITO ELF, then packages them into `vms/qemu/min_kernel_ovmf.fd`, a 4 MiB firmware image. The build script cleans previous guest build artifacts.

In `vms/qemu.sh`, change the absolute path after `-bios` to the generated image on your machine. Keep the launcher as a plain QEMU command: the collector parses it into arguments rather than executing it as a general shell script. The supplied configuration uses one vCPU and 6 GiB of RAM per worker.

### 2. Build and boot the modified host kernel

Prepare a configuration suitable for your machine, including KVM AMD, debugfs, and relay support. For example, start from the running kernel's configuration:

```bash
cd fuzzer/linux
cp /boot/config-"$(uname -r)" .config
make olddefconfig
make menuconfig
cd ..
bash build.sh
```

**`fuzzer/build.sh` builds and installs kernel Debian packages and updates GRUB.** It expects a Debian/Ubuntu-style host and removes existing `.deb`, `.buildinfo`, and `.changes` files in `fuzzer/`. On other distributions, build and install the kernel using the distribution's usual procedure.

Reboot into the newly installed `-ibs` kernel, then check the interfaces:

```bash
sudo modprobe kvm_amd
# If debugfs is not already mounted:
sudo mount -t debugfs debugfs /sys/kernel/debug
ls -l /dev/kvm /dev/svm_ibs_dev
sudo ls /sys/kernel/debug/ibs_logger/
```

The logger exposes per-CPU paths of the form `/sys/kernel/debug/ibs_logger/cpuN/traceN`. If the custom device or logger is missing, check the running kernel, loaded modules, and kernel messages before proceeding.

### 3. Configure storage and CPUs

Before collecting traces:

- Set `LOG_DIR` in `fuzzer/ibs_trace_collect.py` to a dedicated trace directory and create it. The startup check requires that directory to exist and be writable.
- Set `--state-file` to the matching snapshot location. Its default is `/mnt/truenas/ibs_log/fuzz_state.bin`, independent of `LOG_DIR`.
- Select logical CPUs with `--cores`. Each worker starts a single-vCPU QEMU instance pinned to that CPU; account for the per-worker memory allocation.

**A run without `--resume` recursively clears the configured log directory and resets fuzzer progress.** The collector also terminates existing `qemu-system-x86_64` processes at startup and cleanup. Preserve previous results and use a host dedicated to the experiment. Collection stops when free storage falls below 10 GiB.

### 4. Collect traces

For example, after configuring `LOG_DIR` as `/data/ibs/log`:

```bash
cd fuzzer
sudo python3 ibs_trace_collect.py \
  --qemu-script ../vms/qemu.sh \
  --cores 2 \
  --timeout 10 \
  --state-file /data/ibs/log/fuzz_state.bin
```

The collector writes one `.bin` trace per instruction, with instruction bytes encoded in filenames such as `ibs_\x90.bin`. It saves periodic snapshots every ten minutes and logs instructions that hit the inactivity timeout. A timeout triggers a QEMU restart and advances the instruction under test.

To continue using saved progress and preserve existing logs, run from `fuzzer/`:

```bash
sudo python3 ibs_trace_collect.py \
  --qemu-script ../vms/qemu.sh \
  --cores 2 \
  --state-file /data/ibs/log/fuzz_state.bin \
  --resume
```

`--resume` restores the global range snapshot when the specified file exists and requires a per-core snapshot for every selected CPU (for example, `fuzz_state.core2.snapshot.bin`). A missing per-core snapshot causes that worker to fail. Keep the kernel, Python structure definitions, and snapshots from the same revision. Ctrl+C requests worker shutdown; preserve periodic snapshots for recovery.

| Option                  | Behavior                                                   |
| ----------------------- | ---------------------------------------------------------- |
| `--cores 2,4`         | Choose logical CPUs; the default uses all available cores. |
| `--timeout 10`        | Trace inactivity timeout in seconds; `0` disables it.    |
| `--state-file PATH`   | Global snapshot path and base name for per-core snapshots. |
| `--save-state [PATH]` | Save per-core device state and exit.                       |
| `--count-only`        | Report log-file count and average size, then exit.         |

## Analyze collected traces

The Rust analyzer consumes binary traces directly; CSV conversion is optional. Run it on a stable copy or after collection stops to avoid partially written files.

```bash
cd analysis/analyzer
cargo run --release --locked -- \
  /data/ibs/log \
  /data/ibs/findings \
  /data/ibs/analyzer-state \
  /data/ibs/fail-logs
```

The four positional arguments are **input directory**, **findings directory**, **analysis-state directory**, and **failure-log directory**. Their defaults are `/mnt/truenas/ibs_log`, `/mnt/truenas/ibs_findings`, `/mnt/truenas/ibs_state`, and `/mnt/truenas/ibs_fail_logs`.

The analyzer pins workers to CPUs and writes:

- `findings/core-NN/*_finding.json`: source trace path and suspicious samples, including micro-op position, addresses, branch target, and classification reasons.
- `analyzer-state/state.core-NN.json`: processed-file tracking for subsequent runs.
- `fail-logs/failed_files.core-NN.log`: files that could not be analyzed.

Heuristics include register-like addresses, repeated address patterns, uncacheable accesses, changing physical-address bits, and loads followed by branches. Guest-address filtering and micro-op cutoffs are encoded in `analysis/analyzer/src/analyzer.rs`; review them when changing hardware or memory layout. Findings are candidates for manual investigation, not proof of a vulnerability. See [`analysis/filter.md`](analysis/filter.md) for interpretation notes.

Use a new analysis-state directory when reanalyzing changed traces or heuristics so previously processed files are reconsidered.

## Inspect and retest instructions

These helpers contain experiment-specific paths and values and need editing before use:

| Tool                          | How to use it                                                                                                                                                                                                                                        |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fuzzer/bin_to_csv.py`      | Edit `LOG_DIR`, the input `files` list in `main()`, and the output path in `convert_file()`, then run `python3 bin_to_csv.py` from `fuzzer/`. The checked-in version selects one specific trace.                                         |
| `fuzzer/validate_output.py` | Point `log_dir` at converted CSV files, install `tqdm`, then run `python3 validate_output.py`. It expects 513 leading HPA lines and a specific event header. Do not point it at raw binary traces.                                             |
| `analysis/tester.py`        | Edit the selected instruction, register value, QEMU path, and CPU/relay settings, then run `sudo python3 tester.py` from `analysis/`. It uses the custom KVM device and writes `tester_ibs_*.csv`. It also terminates existing QEMU processes. |
| `analysis/filter.py`        | Set `LOG_DIR` and adapt physical-address exclusions, then run `python3 filter.py`. Work on a copy: it rewrites findings and deletes JSON files whose result lists become empty.                                                                  |

The binary format is shared by the kernel logger, `fuzzer/relayfs.py`, and the Rust analyzer. Records include instruction metadata, guest host-physical-address mappings, and IBS events. Keep these definitions synchronized when changing the format.

## License and acknowledgments

The root [`LICENSE`](LICENSE) contains Apache License 2.0. Bundled components retain their own licenses and notices, including the Linux kernel and bootloader sources; consult their source headers and license files when reusing them.

The instruction search builds on Sandsifter's tunneling and page-fault-based length-resolution techniques. COQUITO includes code adapted from the OSDev Wiki, as described in its [original README](coquito/coquito/README.md). See the thesis for research background, methodology, evaluation, and references.
