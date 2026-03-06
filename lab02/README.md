# 🔐 Lab02: Encoded Authenticator — Security Analysis Report

> **SafeTest-Dev | Binary Security Research | Michael.A**
> Reverse Engineering – XMM/SIMD Encoding Analysis & Python Solver

---

## 📄 Overview

This lab analyzes **encoded_authenticator**, a custom authentication binary that uses **XMM SIMD (Single Instruction Multiple Data)** register operations to encode and validate a 32-byte input token. Despite its visually complex disassembly, the encoding scheme is entirely reversible through static analysis — no brute force, no runtime execution needed.

---

## 📁 Report File

| File | Description |
|------|-------------|
| `Lab02_EncodedAuthenticator_Security_Report.docx` | Full professional security report (Word format) |

---

## 🎯 Target Binary

| Property | Value |
|----------|-------|
| Binary Name | `encoded_authenticator` |
| Format | ELF 64-bit LSB Executable |
| Architecture | AMD x86-64 |
| Linkage | Dynamically linked |
| Kernel Requirement | GNU/Linux >= 4.4.0 |
| Entry Point | `0x004010a0` |
| Build ID (SHA1) | `469cedd4d764d7133b430902dd308420bbfdae71` |
| Compiler | GCC 15.2.1 (2026-02-09) |
| Debug Symbols | Stripped |

---

## 🛡️ Security Mitigations (checksec)

| Mitigation | Status |
|------------|--------|
| Stack Canary | ❌ NOT FOUND |
| PIE | ❌ DISABLED — fixed address `0x004010a0` |
| RELRO | ⚠️ Partial only |
| NX (Non-Executable Stack) | ✅ Enabled |
| CFI (SHSTK / IBT) | ❌ Absent |
| RPATH / RUNPATH | ✅ Absent |

> ⚠️ Significantly weaker than Lab01. PIE disabled + no canary = memory corruption also viable as secondary attack path.

---

## 🔍 Findings Summary

| ID | Title | Component | Method | Impact | Severity |
|----|-------|-----------|--------|--------|----------|
| **ECA-01** | Weak Binary Protections | Compiler flags / build config | Static survey | Attack surface expansion | 🟡 **MEDIUM** |
| **ECA-02** | Hardcoded Encoded Secret in .rodata | `.rodata` @ `0x00402030` | `r2 px` memory dump | Full secret extraction | 🟠 **HIGH** |
| **ECA-03** | XMM Encoding Fully Reversible | `fcn.00401230` XMM logic | Python solver (static) | Authentication Bypass | 🔴 **CRITICAL** |

---

## 🔬 Vulnerability Details

### ECA-01 — Weak Binary Protections `MEDIUM`

No stack canary, PIE disabled (fixed address), partial RELRO only.

```bash
$ checksec file encoded_authenticator

Partial RELRO   No Canary Found   NO SHSTK & NO IBT   NX enabled   PIE Disabled
```

---

### ECA-02 — Hardcoded Encoded Secret in .rodata `HIGH`

The 32-byte encoded token is stored verbatim in `.rodata` and fully readable via static inspection:

```bash
[0x004010a0]> px 32 @ 0x402030

0x00402030  7909 e4b4 2af1 eaed d2aa d9ce d39e 1f71
0x00402040  e2e7 2185 18bf 1fb5 c729 5f36 87f2 a5df
```

---

### ECA-03 — XMM Encoding Fully Reversible `CRITICAL`

The `fcn.00401230` function processes input using XMM SIMD:
- Loads hardcoded secret from `.rodata` into `xmm0`
- XORs input with secret bytes via `pxor`
- Shuffles blocks with `punpcklbw`, `punpcklwd`, `punpckldq`, `punpcklqdq`
- Compares result and returns `0` on success

**Because XOR is its own inverse** (`A XOR B XOR B = A`), the valid token is simply the `.rodata` bytes themselves.

**Python Solver:**
```python
# python_solver.py
import sys

payload = bytes([
    0x79,0x09,0xe4,0xb4, 0x2a,0xf1,0xea,0xed,
    0xd2,0xaa,0xd9,0xce, 0xd3,0x9e,0x1f,0x71,
    0xe2,0xe7,0x21,0x85, 0x18,0xbf,0x1f,0xb5,
    0xc7,0x29,0x5f,0x36, 0x87,0xf2,0xa5,0xdf,
])

sys.stdout.buffer.write(payload)
```

**Exploitation:**
```bash
$ python3 python_solver.py | ./encoded_authenticator
OK
# Authentication bypassed. No brute force. No GDB. Pure static analysis.
```

---

## 🧠 Authentication Architecture

```
Input (32 bytes via fread → stdin)
          │
          ▼
  fcn.00401230 — XMM Encoding Routine
  ┌─────────────────────────────────┐
  │  pxor xmm2,xmm2  (zero regs)   │
  │  movdqa xmm0,[0x402030]         │  ← load hardcoded secret
  │  movdqa xmm0,[0x402040]         │  ← second 16-byte block
  │  pxor / punpck* / por           │  ← transform input
  │  cmp rax, 0x20                  │  ← check 32 bytes done
  └─────────────────────────────────┘
          │
    test eax,eax
    ┌─────┴─────┐
    ▼           ▼
   "OK"        "NO"
```

---

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Binary format identification |
| `checksec` | Exploit mitigation survey |
| `strings` | Embedded string extraction |
| `r2 / Radare2` | Full static analysis + disassembly |
| `r2: aaa / afl` | Auto-analysis + function listing |
| `r2: pdf @ main` | Main + encoding function disassembly |
| `r2: px 32` | Raw hex dump of `.rodata` secret |
| `python3` | Token reconstruction solver |

---

## ✅ Recommendations

- **Replace XOR encoding** with HMAC-SHA256 or asymmetric challenge-response
- **Never store secrets in .rodata** — use runtime key derivation or remote auth
- **Enable PIE**: recompile with `-fPIE -pie`
- **Enable Stack Canary**: `-fstack-protector-strong`
- **Enable Full RELRO**: `-Wl,-z,relro,-z,now`

---

## 📊 Risk Matrix

| ID | Likelihood | Impact | Severity |
|----|-----------|--------|----------|
| ECA-01 | Medium | Medium | 🟡 MEDIUM |
| ECA-02 | High | High | 🟠 HIGH |
| ECA-03 | High | Critical | 🔴 CRITICAL |

---

## ⚠️ Disclaimer

All content produced solely for educational and authorized security research purposes within the SafeTest-Dev lab framework. Apply these techniques only to systems for which explicit written authorization has been obtained.

---

## 👤 Author

**Michael.A** — SafeTest-Dev | Binary Security Research
Report Date: March 2026 | Classification: Confidential – Authorized Use Only

---

*SafeTest-Dev | Binary | Reverse | Malware | AI*
