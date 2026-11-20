# Ophion

<div align="center">
  <img src="logo.png" alt="Ophion logo" width="640">
</div>

Ophion is an experimental Type-2 hypervisor for Windows x64. It virtualizes an
already-running Windows system using the CPU's hardware virtualization
extension — **Intel VT-x (VMX)** on Intel CPUs and **AMD-V (SVM)** on AMD
CPUs — and is intended as a systems-programming and virtualization research
project. The backend is selected automatically at load time from the CPU
vendor (`src/cpuinfo.c`, `include/hv_backend.h`).

> **Experimental kernel software:** Hypervisor and kernel-driver defects can
> crash or corrupt the system. Build and evaluate Ophion only on a dedicated
> test machine or isolated environment with no important data. Ophion is not
> intended to bypass anti-cheat, endpoint-security, or other third-party
> integrity controls. No compatibility or undetectability claims are made.

## Project status

This project is under active development and has only been exercised on the
hardware and Windows configuration listed below. It is not production-ready;
correctness, stability, and compatibility on other systems are not guaranteed.
The [compatibility table](#compatibility) below describes the design targets.

## Technical overview

- **Dual backend:** Intel VT-x (VMX) and AMD-V (SVM) backends behind a common
  `HV_BACKEND` vtable, selected at load time from the CPU vendor. Both
  virtualize every logical processor in every processor group.
- **Per-processor virtualization:** Uses documented Windows 7+ group-affinity
  enumeration (`KeGetProcessorNumberFromIndex` + `KeSetSystemGroupAffinityThread`)
  to initialize and terminate virtualization on every logical processor across
  all processor groups, with S3/S4 power-state (`\Callback\PowerState`) and CPU
  hot-add (`KeRegisterProcessorChangeCallback`) support.
- **EPT / NPT:** Builds a dynamic identity map (1 GB huge pages where supported,
  2 MB large pages, split to 4 KB on MTRR/RAM boundaries) using true Intel EPT
  format on Intel and true x86-64 NPT format (with `IA32_PAT`-derived caching)
  on AMD. Unmapped above-4G MMIO (64-bit PCIe / Resizable BARs) is lazily mapped
  as UC from a pre-allocated root-mode pool, and 4 KB EPT/NPT watchpoints are
  supported on both backends.
- **VMX lifecycle:** Allocates and configures VMXON regions, VMCS state, and
  XSS-exiting bitmaps, enables per-LP `IA32_FEATURE_CONTROL`, launches guests,
  and cleanly restores live guest state during teardown.
- **SVM lifecycle:** Runs an AMD APM-compliant `VMLOAD`/`VMRUN`/`VMSAVE` host
  loop with per-LP VMCB, host VMCB, HSAVE, IOPM, and programmed MSRPM; exits
  SVM cleanly on unload so all structures can be freed safely.
- **VM-exit / #VMEXIT handling:** Shared backend-neutral exit policy
  (`vmexit_common.c`), per-vCPU cycle profiler, dynamic MSR tracing, and a
  lock-free root-mode ring-buffer logger (`logbuf.c`) with zero Windows API
  calls in root/host mode.
- **Host-state isolation:** Minimal private host page tables (4-level and LA57
  5-level), per-core 32 KB-aligned VMM stacks with per-core host NMI tracking,
  diagnostic host fault capture (`HOST_FAULT_INFO`), and per-core private GDTs.
- **Capability-aware controls:** All VMX control bits are adjusted against the
  CPU's capability MSRs; VPID/EPT/secondary-controls use is verified at
  runtime and dependent paths (e.g. INVVPID) are guarded. Machines without
  the required features fail cleanly at load with a diagnostic.
- **Version portability:** No hardcoded kernel structure offsets;
  `ExAllocatePool2` is resolved dynamically with an `ExAllocatePoolWithTag`
  fallback, so the driver loads on Windows 7 x64 through Windows 11 24H2.

The implementation also contains experimental build-time options that alter
selected guest-visible processor state. These are provided for controlled
virtualization research; they do not imply compatibility with or bypass of any
third-party product.

## Architecture

| Path | Responsibility |
|---|---|
| `include/hv.h` | Shared declarations and function prototypes |
| `include/hv_types.h` | Per-processor state and virtualization structures |
| `include/ia32.h` | Intel architecture definitions |
| `include/stealth.h` | Build-time feature options and related state |
| `include/asm_prototypes.h` | Prototypes for assembly routines |
| `src/driver.c` | Windows driver entry point, backend selection, device setup, and status IOCTLs |
| `src/cpuinfo.c` | CPU vendor detection and virtualization capability probing (Intel/AMD) |
| `src/win_compat.c` | Windows version compatibility layer (dynamic APIs, pool wrappers, processor-group broadcast) |
| `src/vmx.c` | Intel VMX backend: VMXON, VMCS configuration, and lifecycle |
| `src/svm.c` | AMD SVM backend: VMCB/VMRUN, NPT, and #VMEXIT handling |
| `src/vmexit.c` | VMX VM-exit dispatch and instruction handling |
| `src/ept.c` | Dynamic identity-mapped EPT/NPT (RAM-range driven), memory typing, page splitting |
| `src/events.c` | Exception and interrupt injection |
| `src/broadcast.c` | All-groups DPC broadcast for initialization and termination |
| `src/hostcr3.c` | Private host page-table construction |
| `src/hostidt.c` | Private host IDT construction |
| `src/hostgdt.c` | Per-processor private host GDT construction |
| `src/stealth.c` | CPUID cache initialization and processor-state validation |
| `src/util.c`, `src/globals.c` | Shared utilities and global state |
| `asm/` | x64 MASM routines for VMX/SVM operations, context handling, and segments |
| `include/hv_backend.h` | Backend abstraction (VMX vs SVM vtable) |
| `include/hv_ioctl.h` | Shared kernel/usermode IOCTL codes and diagnostics structs |
| `include/svm.h` | AMD SVM VMCB layout, compressed segment attributes, MSRPM helpers |
| `src/vmexit_common.c` | Shared VMX/SVM exit policy (CPUID, XSETBV, VMCALL auth, CR checks, MSR tracing) |
| `src/logbuf.c` | Lock-free root-mode ring-buffer event logger |
| `tools/ophion-cli/ophion_cli.c` | Usermode CLI for status, exit profiler stats, log draining, watchpoints, and MSR tracing |
| `tests/unit_tests.c` | Host-side unit test suite verifying MTRR, XCR0, CR, CPUID, SVM, and ring-buffer logic |

## Compatibility

Ophion is designed to run on a wide range of machines and Windows versions:

| Dimension | Support |
|---|---|
| CPU vendor | Intel (VT-x/VMX **and** EPT required) and AMD (SVM **and** nested paging required). Other vendors: clean load failure with `STATUS_NOT_SUPPORTED`. |
| CPU models | Intel Nehalem (2008) and newer; AMD Family 10h (2007) and newer. CPUs without EPT/NPT fail cleanly at load. |
| Logical processors | Any count, including multi-group systems with more than 64 logical processors (all processor groups are virtualized via per-group DPC broadcast). |
| Physical memory | Any size. The identity-mapped EPT/NPT is built dynamically from the actual RAM ranges (`MmGetPhysicalMemoryRanges`), so machines with more than 512 GB RAM and LA57 (5-level paging) systems work. Physical addresses up to 48 bits (256 TB) are mapped by the 4-level walk. |
| Firmware | VT-x/SVM must be enabled in BIOS/UEFI. If `IA32_FEATURE_CONTROL` is unlocked, Ophion enables VMX itself; if it is locked off (or Hyper-V/VBS owns VMX), the driver fails cleanly without touching the system. AMD SVM locked via `VM_CR` fails cleanly. |
| Windows | x64 Windows 7 SP1 through Windows 11 24H2 and Server 2016–2025. `ExAllocatePool2` is resolved dynamically (falls back to `ExAllocatePoolWithTag` on pre-2004 systems); no hardcoded kernel structure offsets are used anywhere, so build-to-build layout changes do not matter. Test signing must be enabled (`bcdedit /set testsigning on`) and Secure Boot off (or the test certificate enrolled), since this is a development-signed driver. On Windows 11 with HVCI/Memory Integrity enabled, unsigned or test-signed drivers are blocked by policy — disable HVCI to load a development build. |
| Running under a hypervisor | If the machine is itself a VM with nested virtualization exposed (e.g. Hyper-V with nested virt), Ophion can virtualize that guest too. If Hyper-V is active on the host without nested VT-x/SVM exposed, Ophion fails cleanly. |

## Requirements

- x64 CPU with hardware virtualization enabled in firmware (Intel VT-x + EPT,
  or AMD SVM + NPT).
- Windows x64 (see compatibility table above).
- Visual Studio 2022 with the Desktop development with C++ workload.
- Windows Driver Kit (WDK) and Windows SDK `10.0.26100.0`.
- x64 MASM tools installed with Visual Studio.

## Build

From a Visual Studio Developer Command Prompt:

```bat
MSBuild.exe Ophion.sln /p:Configuration=Release /p:Platform=x64
```

The project is configured to produce `Ophion.sys` under
`build\bin\Release\`. The driver uses test signing; this is a development
configuration, not a production signing process.

## Configuration

Compile-time options are defined in [`include/stealth.h`](include/stealth.h).
For example, the timing-compensation option is disabled by default, while
several other experimental options are enabled. Review the definitions and
their implementation before building; configuration changes have not been
validated across a broad range of systems.

## Tested configuration

- Intel Core i5-14400F
- Windows 10 x64

This is a limited test report, not a supported-hardware list or a guarantee of
compatibility. The compatibility table above describes the design targets;
please report machines/OS builds where Ophion fails to load or virtualize.

## Further reading

[Ophion — Building a Stealth Intel VT-x Hypervisor for Windows](https://websec.net/blog/ophion-building-a-stealth-intel-vt-x-hypervisor-for-windows-69b62daa7462693131828c97)

The article describes the project’s design and development. Its title reflects
the original article; Ophion makes no claim that it can evade detection or
operate with third-party security products.

## Acknowledgements

- [HyperDbg](https://github.com/HyperDbg/HyperDbg) — Reference for VMX
  architecture and VM-exit handling patterns.
- [humzak711](https://github.com/humzak711) — Feedback on processor feature
  handling.
- [VMAware](https://github.com/kernelwernel/VMAware) and
  [hvdetecc](https://github.com/can1357/hvdetecc) — Tools used during
  development and testing.
- [Claude](https://claude.ai) — Debugging assistance and architecture
  research.

## License

Ophion is licensed under the [MIT License](LICENSE).
