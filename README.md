# ⚡ FORKBOX

**Deterministic, sub-millisecond execution runtime & sandboxing engine for Autonomous AI Agents.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75+-black?logo=rust)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)](https://python.org)
[![Linux Kernel](https://img.shields.io/badge/Kernel-Linux%205.15+-orange?logo=linux)](https://kernel.org)

Traditional container runtimes (Docker/containerd) introduce unacceptable latency overhead (~400ms per cold boot) for recursive agent workflows (e.g., Tree-of-Thought, SWE-bench, Code Execution). Heavy MicroVMs (Firecracker/gVisor) mitigate security concerns but penalize boot latency and consume excessive RAM.

**Forkbox** provides a hardened, rootless micro-sandbox designed specifically for ephemeral agent task execution, delivering up to **500x faster startup times** than Docker with zero host disk contamination.

---

## 📊 Benchmarks (Real Hardware Validation)

Measured on bare-metal Ubuntu Linux (x86_64), execution: `exit 0` / Python compute:

| Runtime Engine | Isolation Boundary | Cold Boot Latency | Speedup vs Docker |
| :--- | :--- | :--- | :--- |
| **Docker** (`alpine:latest`) | Namespaces + Daemon (runc) | **409.44 ms** | 1.0x (Baseline) |
| **Forkbox (Python 3.12 Runtime)** | Rootless UserNS + Ephemeral OverlayFS | **26.39 ms** | **15.5x faster** |
| **Forkbox (Hardened Shell)** | UserNS + Seccomp-BPF + Cgroups v2 | **2.97 ms** | **137.8x faster** |
| **Forkbox (RAW Isolation Hot-Path)**| Direct Kernel Fork + CoW Pages | **0.713 ms (713 µs)**| **574.0x faster** |

*Anti-DoS Watchdog precision: 500ms target killed at **500.45 ms** (+450 µs jitter).*

---

## 🛡️ Architectural Pillars

* **Zygote Warm Pre-Mounting**: Pre-warms base kernel namespaces (`PID`, `NET`, `IPC`, `UTS`) in physical memory. Instances branch out via Copy-on-Write (`fork()`) bypassing dynamic linker (`ld.so`) overhead.
* **Ephemeral RAM OverlayFS**: The host filesystem serves as an immutable `lowerdir=/`. Each sandbox executes with an isolated `upperdir` and `workdir` mounted on `tmpfs`. File mutations vanish completely on process termination.
* **Ring 0 Seccomp-BPF Filtering**: Injects compiled BPF bytecode directly into the kernel before execution. High-risk escape vectors (`mount`, `ptrace`, `bpf`, `reboot`, `init_module`) return deterministic `EPERM` errors.
* **100% Rootless (Zero `sudo`)**: Built natively on Linux User Namespaces (`CLONE_NEWUSER`). Unprivileged host users (`UID 1000`) safely obtain mapped `UID 0` privileges confined strictly inside the sandbox jail.
* **Sub-Millisecond Watchdog**: Async event-loop monitors executions via non-blocking IPC pipes, delivering microsecond-precision `SIGKILL` termination against infinite loops (`while true`) and DoS scripts.

---

## 🚀 Quickstart

### 1. Build the Rust Engine

```bash
# Clone and compile optimized binary
git clone [https://github.com/matheusdelgado/forkbox.git](https://github.com/matheusdelgado/forkbox.git)
cd forkbox
cargo build --release
```

### 2. Start the Daemon

The daemon manages rootless namespaces and listens on `/tmp/forkbox.sock`:

```bash
./target/release/forkbox daemon
```

### 3. Install the Python SDK

In your agent environment:

```bash
pip install -e .
```

### 4. Use in Python (LangChain, AutoGen, or Raw Code)

```python
from forkbox import Forkbox

# 1. Safe arbitrary code execution
res = Forkbox.run("python3 -c 'import math; print(math.factorial(20))'")
print(res.stdout)      # "2432902008176640000"
print(f"Time: {res.duration_ms:.2f}ms")  # ~26 ms

# 2. Strict DoS containment (Terminated automatically in 500ms)
res_loop = Forkbox.run("while true; do :; done", timeout_ms=500)
print(res_loop.timed_out)   # True
print(res_loop.exit_code)   # 124

# 3. Security check: Host system is completely untouchable
res_hack = Forkbox.run("echo 'payload' >> /etc/hosts")
# Writes happen in ephemeral RAM (OverlayFS) and evaporate on exit.
```

---

## 🔒 Security Architecture

```
[ Unprivileged Agent Code / Python Script ]
                      │
                      ▼
[ Seccomp-BPF Jail ] ── (Blocks: ptrace, bpf, reboot, mount, kexec)
                      │
                      ▼
[ User Namespace (CLONE_NEWUSER) ] ── (Host UID 1000 -> Jail UID 0)
                      │
                      ▼
[ Ephemeral OverlayFS ] ── (upperdir: tmpfs in RAM | lowerdir: /)
                      │
                      ▼
         [ Linux Kernel (Ring 0) ]
```

---

## 📄 License

MIT License. Designed for deep-tech agent infrastructure.