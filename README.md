# Ophion

<div align="center">
  <img src="logo.png" alt="Ophion logo" width="640">
</div>

Ophion is an experimental Intel VT-x Type-2 hypervisor for Windows x64. It
virtualizes an already-running Windows system and is intended as a
systems-programming and virtualization research project.

> **Experimental kernel software:** Hypervisor and kernel-driver defects can
> crash or corrupt the system. Build and evaluate Ophion only on a dedicated
> test machine or isolated environment with no important data. Ophion is not
> intended to bypass anti-cheat, endpoint-security, or other third-party
> integrity controls. No compatibility or undetectability claims are made.

## Project status

This project is under active development and has only been exercised on the
hardware and Windows configuration listed below. It is not production-ready;
correctness, stability, and compatibility on other systems are not guaranteed.

## Technical overview

- **Per-processor virtualization:** Uses a DPC broadcast to initialize and
  terminate VMX on logical processors.
- **Extended Page Tables (EPT):** Builds an identity map using 2 MB pages,
  derives memory types from MTRRs, and supports splitting large pages.
- **VMX lifecycle:** Allocates and configures VMXON regions and VMCS state,
  launches guests, and restores guest state during teardown.
- **VM-exit and event handling:** Implements handlers for selected CPUID,
  control-register, debug-register, MSR, EPT, interrupt, and exception events.
- **Host-state isolation:** Includes private host page tables, an IDT, and
  per-processor GDTs for VMX-root operation.
- **Capability-aware controls:** Checks processor capabilities and configures
  supported VMX, EPT, and VPID features.

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
| `src/driver.c` | Windows driver entry point, device setup, and status IOCTL |
| `src/vmx.c` | VMX initialization, VMCS configuration, and lifecycle |
| `src/vmexit.c` | VM-exit dispatch and instruction handling |
| `src/ept.c` | EPT setup, memory typing, and page management |
| `src/events.c` | Exception and interrupt injection |
| `src/broadcast.c` | Multi-processor initialization and termination |
| `src/hostcr3.c` | Private host page-table construction |
| `src/hostidt.c` | Private host IDT construction |
| `src/hostgdt.c` | Per-processor private host GDT construction |
| `src/stealth.c` | CPUID cache initialization and processor-state validation |
| `src/util.c`, `src/globals.c` | Shared utilities and global state |
| `asm/` | x64 MASM routines for VMX operations, context handling, and segments |

## Requirements

- x64 Intel processor with Intel VT-x and the required EPT capabilities enabled
  in firmware.
- Windows x64.
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
compatibility.

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
