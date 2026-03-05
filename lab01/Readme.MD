# 🔐 Lab01: Secure Boot Validator — Security Analysis Report

> **SafeTest-Dev | Binary Security Research | Michael.A**  
> Reverse Engineering – Product Security Case Study

---

## 📄 Overview

This repository contains the full security analysis report for **Lab01: Secure Boot Validator**, a reverse engineering case study targeting a trust enforcement binary. The assessment covers static reconnaissance, disassembly analysis, and dynamic runtime exploitation — resulting in three confirmed vulnerabilities that collectively allow complete authentication bypass.

---

## 📁 Report File

| File | Description |
|------|-------------|
| `Lab01_SecureBootValidator_Security_Report.docx` | Full professional security report (Pdf format) |

---

## 🎯 Target Binary

| Property | Value |
|----------|-------|
| Binary Name | `secure_boot_validator` |
| Format | ELF 64-bit LSB PIE Executable |
| Architecture | AMD x86-64 |
| Linkage | Dynamically linked |
| Kernel Requirement | GNU/Linux >= 4.4.0 |
| Entry Point | `0x1260` |
| Build ID (SHA1) | `5f7538854e9459d419f1618b0d8575c23100d331` |
| Debug Symbols | Stripped |

---

## 🛡️ Security Mitigations Present

| Mitigation | Status |
|------------|--------|
| Stack Canary | ✅ Enabled |
| NX (Non-Executable Stack) | ✅ Enabled |
| PIE / ASLR | ✅ Enabled |
| Full RELRO | ✅ Enabled |
| RPATH / RUNPATH | ✅ Absent |
| CFI (SHSTK / IBT) | ❌ Disabled |
| Debug Symbols | ❌ Stripped |

> ⚠️ Despite strong memory-safety mitigations, **none of these protect against logic-level predicate manipulation** — the primary attack surface identified in this lab.

---

## 🔍 Findings Summary

| ID | Title | Affected Component | Attack Method | Impact | Severity |
|----|-------|--------------------|---------------|--------|----------|
| **SBV-01** | Single Predicate-Based Trust Decision | Flag Evaluation Logic | Branch Inversion | Authentication Bypass | 🟠 **HIGH** |
| **SBV-02** | Runtime Register Manipulation | Predicate Register State | Debugger State Modification | Temporary Trust Escalation | 🟡 **MEDIUM** |
| **SBV-03** | Predicate Manipulation via Instruction Patching | Validation Logic Instruction | Condition Forcing (opcode patch) | Persistent Authentication Bypass | 🔴 **CRITICAL** |

---

## 🔬 Vulnerability Details

### SBV-01 — Single Predicate-Based Trust Decision `HIGH`

The entire authentication mechanism is gated behind a single `test al, al` instruction at virtual address `0x5555555551f5`. The subsequent `jne` determines the trust decision with no redundancy.

**Critical instruction:**
```asm
11f5: 84 c0    test %al, %al    ; evaluate low byte of hash
11f7: 75 24    jne  121d        ; if AL != 0 → FAILURE branch
```

Any method that forces `AL = 0x00` at this point bypasses authentication unconditionally.

---

### SBV-02 — Runtime Register Manipulation `MEDIUM`

By attaching GDB and placing a breakpoint at the predicate instruction, an attacker can forcibly set `$rax = 0` before the trust decision — causing `test al, al` to set `ZF=1` and fall through to the success path.

**Exploitation:**
```bash
$ gdb ./secure_boot_validator
(gdb) b *0x5555555551f5
(gdb) continue
# Enter any invalid token when prompted
(gdb) set $rax = 0
(gdb) continue
# Output: Validation successful. Secure boot unlocked.
```

> Limitation: Requires debugger attachment; does not persist across restarts.

---

### SBV-03 — Predicate Manipulation via Instruction Patching `CRITICAL`

A single byte overwrite at file offset `0x11f7` permanently inverts the branch logic — changing `jne` (`0x75`) to `je` (`0x74`). All future executions of the patched binary accept **any arbitrary input** as valid.

**Exploitation:**
```bash
# Verify original opcode
$ xxd -g 1 -s +0x11f0 -l 16 secure_boot_validator
000011f0: ... 84 c0 75 24 ...   # 0x75 = jne

# Patch: overwrite 0x75 → 0x74
$ printf '\x74' | dd of=secure_boot_validator bs=1 seek=$((0x11f7)) count=1 conv=notrunc

# Verify patch
$ xxd -g 1 -s +0x11f0 -l 16 secure_boot_validator
000011f0: ... 84 c0 74 24 ...   # 0x74 = je (PATCHED)

# Execute — any input now succeeds
$ ./secure_boot_validator
Enter authorization token: thisisrandominputanything
Validation successful. Secure boot unlocked.
```

---

## 🧠 Validation Architecture

```
Input Entity (Token/Firmware/Payload)
          │
          ▼
  Pre-Validation
  (Length Check / Format Check / Newline Strip)
          │
          ▼
  Predicate Engine
  (Hash Mixing: XOR, ROL, IMUL, SHR with constants
   0xdeadbeefcafebabe and 0x9e3779b97f4a7c15)
          │
          ▼
  Flag Evaluation
  (test al, al → Zero Flag)
          │
    ┌─────┴─────┐
    ▼           ▼
Trust         Trust
Granted       Rejected
(Continue)    (Abort)
```

---

## 🔧 Reconnaissance Commands Used

```bash
# Binary identification
file secure_boot_validator | sed 's/,/\n/g' | sed 's/^ *//' | tee output/file_metadata.txt

# Mitigation survey
checksec file secure_boot_validator --output json | jq . | tee output/checksec.json

# ELF header
readelf -h secure_boot_validator | tee output/readelf_header_raw.txt

# Program headers & segment mapping
readelf -l secure_boot_validator

# Full disassembly
objdump -d secure_boot_validator

# Hex inspection
xxd -g 1 -s +0x11e0 -l 64 secure_boot_validator | tee output/hex_check_before.txt
```

---

## 🛠️ Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| `file` | — | Binary format identification |
| `checksec` | — | Exploit mitigation survey |
| `readelf` | binutils | ELF header & section analysis |
| `objdump` | binutils | Static disassembly |
| `xxd` | — | Hex dump & offset inspection |
| `GDB` | 17.1 | Dynamic analysis & register manipulation |
| `printf` + `dd` | — | Binary patching (opcode overwrite) |

---

## ✅ Recommendations

### Immediate (Critical & High)

- **Multi-Stage Verification** — Replace the single predicate gate with independent verification checkpoints at multiple pipeline stages.
- **Binary Integrity Check** — Compute and verify HMAC-SHA256 of the binary at startup; reject execution if tampered.
- **Hardware CFI** — Enable CET SHSTK + IBT via `-fcf-protection=full` to harden against branch manipulation.
- **Cryptographic Token Validation** — Replace the custom hash with HMAC-based authentication (e.g., HMAC-SHA256 with a server-held secret).

### Medium-Term

- Anti-debugging mechanisms (`ptrace` detection)
- Control-flow flattening / opaque predicates
- OS-level signed binary enforcement (dm-verity, IMA/EVM)
- Runtime self-integrity checksums over critical code regions

---

## 📊 Risk Matrix

| ID | Likelihood | Impact | Severity |
|----|-----------|--------|----------|
| SBV-01 | High | High | 🟠 HIGH |
| SBV-02 | Medium | Medium | 🟡 MEDIUM |
| SBV-03 | High | Critical | 🔴 CRITICAL |

---

## ⚠️ Disclaimer

This report and all techniques documented herein were produced **solely for educational and authorized security research purposes** within the SafeTest-Dev lab framework. All analysis was performed in an isolated environment on a sample binary provided expressly for reverse engineering training.

**These techniques must only be applied to systems for which explicit written authorization has been obtained.**

---

## 👤 Author

**Michael.A** — SafeTest-Dev | Binary Security Research  
Report Date: March 2026  
Classification: Open/Public

---

*SafeTest-Dev | Binary | Reverse | Malware | AI*
