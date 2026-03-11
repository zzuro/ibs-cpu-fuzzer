## Potential Indicators and Observations

* **Physical address outside the guest memory range**
  → Possible **escape** from the guest environment.

* **Physical address changes across the 5 runs**
  → Possibly **register-dependent address calculation**.

* **Same linear address (or linear address = 0) but different physical address**
  → Possibly **register-dependent access** or **different address translation**.

* **Physical address closely resembles a register value**
  → Possibly **direct use of a register in the address calculation**.

* **Branch address changes across the 5 runs**
  → Possibly **register-dependent control flow**.

* **`branch_target_rip` resembles a register value**
  → Possibly an **indirect jump via a register value**
  *(particularly interesting if this results in a jump from user space into the kernel).*

* **Load followed by a branch**
  → Possible **data-dependent control flow**.

* **Load followed by a mispredicted branch**
  → Possibly **speculative execution dependent on the loaded data**.

* **Most significant bits (MSBs) of the physical address change**
  → Access to **different physical frames** or **control bits**.


* **`dc_uc_mem_acc = 1`**
  → Possible access to an **MMIO region** or **unusual memory access**.

* **Suspicious physical address (e.g., `0x6c6c6c6c`)**
  → Possibly **stack or guest memory interpreted as an address**.

* **Suspicious `branch_target_rip` (e.g.,`0x6c6c6c6c`)**
  → Possibly **stack or guest memory used as a branch target**.

* **Register contents change across the 5 runs**
  → Possibly **corrupted instruction state**.
