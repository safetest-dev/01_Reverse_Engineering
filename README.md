# 🔬 01_Reverse_Engineering
> **SafeTest-Dev | Binary Security Research**  
> A structured collection of reverse engineering labs covering binary analysis, malware inspection, and product security research.

---

## 📖 About This Repository

This repository is a hands-on reverse engineering research collection maintained by **SafeTest-Dev**. Each lab folder contains a self-contained case study targeting a specific binary, firmware, or executable artifact — documenting the full methodology from initial reconnaissance through exploitation and remediation.

Labs are designed for:
- 🎓 Security researchers and students learning binary analysis
- 🛠️ Practitioners studying real-world trust enforcement mechanisms
- 📋 Reference material for product security assessments

---

## 🧪 Labs Index

| # | Lab | Target | Type | Techniques | Severity |
|---|-----|--------|------|------------|----------|
| [Lab01](./lab01/) | Secure Boot Validator | ELF 64-bit Linux Binary | Authentication Bypass | Static Disassembly, GDB, Binary Patching | 🔴 Critical |
| [Lab02](./lab02/) | Encoded Authenticator | ELF 64-bit Linux Binary | Authentication Bypass | Static Disassembly, Radare2, XOR Decoding, Python Solver | 🔴 Critical |
| [Lab03](./lab03/) | Algorithm Check | ELF 64-bit Linux Binary | Authentication Bypass | Static Disassembly, Radare2, ROR+XOR+Modular Arithmetic, Python Solver | 🔴 Critical |
| [Lab04](./lab04/) | Secure Loader v2.1 | PE32+ Windows Binary | Authentication Bypass | Static Disassembly, Radare2, Wine, NOP Injection, Binary Patching | 🔴 Critical |
| [Lab05](./lab05/) | DLL Key XOR Decode | PE32+ Windows Binary + DLL | Two-Stage Key Bypass | Static Disassembly, Radare2, Wine, XOR Brute Force, hexor (Crystal) | 🔴 Critical |
| [Lab06](./lab06/) | Notepad++ v8.9.3 Installer | PE32+ NSIS Windows Installer | Control Flow + String Manipulation | Static Disassembly, Radare2, Wine, Jump Redirect, UTF-16LE String Patch | 🔴 Critical |

> New labs are added progressively. Each lab follows the same structured methodology.

---

## 🔍 Methodology

Every lab in this repository follows a consistent analysis pipeline:

```
1. RECONNAISSANCE
   └── file, checksec, readelf, strings, wine

2. STATIC ANALYSIS
   └── Radare2 (r2), objdump, Ghidra, IDA, Binary Ninja

3. DYNAMIC ANALYSIS
   └── GDB, ltrace, strace, Frida, Wine

4. EXPLOITATION
   └── Patch, inject, manipulate, bypass

5. DOCUMENTATION
   └── Full report (.pdf) + README + artifacts
```

---

## 📋 Lab Summaries

### Lab03 — Algorithm Check
**Target:** `algorithm_check` (ELF 64-bit, x86-64)  
**Key Finding:** Multi-step transform (ROR + XOR + modular multiply) fully invertible via Python solver. All 32-byte target constants stored in `.rodata`. Token recovered in <1 second with zero runtime interaction.  
**Flags:** `ACCESS GRANTED`

### Lab04 — Secure Loader v2.1 (Binary Patching)
**Target:** `loader.exe` (PE32+, x86-64, Stripped)  
**Key Finding:** Key validation implemented as a local `strcmp` + `JNE` gate. Replacing 2 bytes at `0x140002bad` (JNE → NOP NOP) bypasses authentication entirely with any input.  
**Flags:** `FLAG{STAGE1_PASS}`

### Lab05 — DLL Key XOR Decode (Two-Stage)
**Target:** `loader.exe` (Stage 1) + `payload.dll` (Stage 2)  
**Key Finding:** Stage 2 DLL key stored as XOR-encoded 64-bit constant (`0x335157414d5b53`) in `.text` section. Single-byte XOR keyspace = 255 values — exhausted instantly by `hexor` (custom Crystal tool). Key `0x12` → `AI_SEC!`.  
**Flags:** `FLAG{STAGE1_PASS}` + `FLAG{STAGE2_DLL_PASS}`

### Lab06 — Notepad++ v8.9.3 Installer (Real-World)
**Target:** `npp.8.9.3.Installer.x64.exe` (PE32+, NSIS-based)  
**Key Finding (1):** NSIS integrity check implemented as a single `je` at `0x0040337f` — redirected to bypass with 2-byte `jmp` patch.  
**Key Finding (2):** NSIS error string stored as UTF-16LE in writable `.data` at `0x0040a098` — overwritten with `POC-1 GOT IT`. Confirmed in NSIS error dialog on re-execution.  
**POC:** `POC-1 GOT IT` displayed in NSIS Error dialog

---

## 🛠️ Common Tools Used Across Labs

| Category | Tools |
|----------|-------|
| **Identification** | `file`, `xxd`, `strings`, `binwalk`, `checksec` |
| **Disassembly** | `Radare2 (r2)`, `objdump`, `Ghidra`, `IDA Pro`, `Binary Ninja` |
| **Debugging** | `GDB` (with pwndbg/peda), `ltrace`, `strace` |
| **Execution** | `Wine` (PE32+ on Linux), `gdb` |
| **Patching** | `r2: wa`, `r2: wx`, `r2: oo+`, `dd`, `python`, `pwntools` |
| **Custom Tools** | `hexor` (Crystal — XOR brute force decoder) |
| **Dynamic** | `Frida`, `angr`, `Unicorn` |

---

## 📂 Lab Types (Planned)

| Type | Description |
|------|-------------|
| 🐧 **ELF Binary** | Linux executables — authentication, license checks, validators |
| 🪟 **PE Binary** | Windows executables — keygens, CrackMe, protection schemes |
| 📦 **Firmware** | Embedded firmware — UART extraction, filesystem analysis |
| 🔌 **Shared Library** | `.so` / `.dll` — hooking, symbol hijacking |
| 🐍 **Scripted Payload** | Python bytecode, Lua, compiled scripts |
| 📱 **APK / DEX** | Android reverse engineering |

---

## ⚠️ Disclaimer

All content in this repository is created **solely for educational and authorized security research purposes** under the SafeTest-Dev lab framework.

- ✅ All binaries analyzed are purpose-built lab samples or analyzed in a controlled environment
- ✅ All techniques are documented for defensive understanding and incident response
- ❌ Do **not** apply these techniques to systems without explicit written authorization

---

## 👤 Author

**Michael.A** — SafeTest-Dev  
Binary | Reverse | Malware | Exploitation | AI

---

*SafeTest-Dev © 2026 — All rights reserved*
