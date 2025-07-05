# PhantomInjector - Advanced In-Memory Process Injection Framework

![Red Team](https://img.shields.io/badge/Use-Red_Team-orange) ![License](https://img.shields.io/badge/License-MIT-blue) ![OS](https://img.shields.io/badge/OS-Windows-lightgrey)

A stealthy PowerShell-based process injection framework implementing multiple in-memory techniques with evasion capabilities, designed for red team engagements and penetration testing.

## Features

- **Multiple Injection Techniques**:
  - APC Injection (Early Bird + QueueUserAPC)
  - Thread Hijacking with crash protection
  - Process Ghosting (no disk writes)
  - Classic Remote Thread Injection

- **Evasion Capabilities**:
  - AMSI bypass via function patching
  - ETW bypass via `EtwEventWrite` hooking
  - NTDLL unhooking from disk
  - Direct syscall support (via in-memory assembly)

- **Operational Security**:
  - Anti-debug checks
  - Sandbox detection
  - Dynamic payload loading

## Architecture

```mermaid
graph TD
    A[Payload Source] --> B{Local/Remote}
    B --> C[Local File]
    B --> D[Web Download]
    C --> E[In-Memory Load]
    D --> E
    E --> F[Evasion Checks]
    F --> G[Injection Method]
    G --> H[APC/ThreadHijack/Ghosting/RemoteThread]
    H --> I[Shellcode Execution]

