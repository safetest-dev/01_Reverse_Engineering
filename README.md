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

## 🗂️ Repository Structure

```
01_Reverse_Engineering/
│
├── lab01/                        # Secure Boot Validator
│   ├── secure_boot_validator     # Target binary
│   ├── output/                   # Analysis artifacts
│   │   ├── file_metadata.txt
│   │   ├── checksec.json
│   │   ├── readelf_header_raw.txt
│   │   ├── hex_check_before.txt
│   │   └── hex_check_after.txt
│   ├── README.md                 # Lab-specific report
│   └── Lab01_SecureBootValidator_Security_Report.docx
│
├── lab02/                        # Coming Soon
├── lab03/                        # Coming Soon
│
└── README.md                     ← You are here
```

---

## 🧪 Labs Index

| # | Lab | Target | Type | Techniques | Severity |
|---|-----|--------|------|------------|----------|
| [Lab01](./lab01/) | Secure Boot Validator | ELF 64-bit Linux Binary | Authentication Bypass | Static Disassembly, GDB, Binary Patching | 🔴 Critical |
| [Lab02](./lab02/) | Encoded Authenticator | ELF 64-bit Linux Binary | Authentication Bypass | Static Disassembly, Radare2, XOR Decoding, Python Solver | 🔴 Critical |
| Lab03 | *(Coming Soon)* |— | — | — | — |

> New labs are added progressively. Each lab follows the same structured methodology.

---

## 🔍 Methodology

Every lab in this repository follows a consistent analysis pipeline:

```
1. RECONNAISSANCE
   └── file, checksec, readelf, strings, strace

2. STATIC ANALYSIS
   └── objdump, Ghidra, IDA, Binary Ninja

3. DYNAMIC ANALYSIS
   └── GDB, ltrace, strace, Frida

4. EXPLOITATION
   └── Patch, inject, manipulate, bypass

5. DOCUMENTATION
   └── Full report (.docx) + README + artifacts
```

---

## 🛠️ Common Tools Used Across Labs

| Category | Tools |
|----------|-------|
| **Identification** | `file`, `xxd`, `strings`, `binwalk` |
| **Mitigations** | `checksec`, `readelf` |
| **Disassembly** | `objdump`, `Ghidra`, `IDA Pro`, `Binary Ninja` |
| **Debugging** | `GDB` (with pwndbg/peda), `ltrace`, `strace` |
| **Patching** | `dd`, `printf`, `python`, `pwntools` |
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

- ✅ All binaries analyzed are purpose-built lab samples
- ✅ All techniques are documented for defensive understanding
- ❌ Do **not** apply these techniques to systems without explicit written authorization

---

## 👤 Author

**Michael.A** — SafeTest-Dev  
Binary | Reverse | Malware | AI

---

*SafeTest-Dev © 2026 — All rights reserved*
