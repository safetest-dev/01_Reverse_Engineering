# 🔐 Lab03: Algorithm Check — Security Analysis Report

> **SafeTest-Dev | Binary Security Research | Michael.A**
> Reverse Engineering — Multi-Step Transformation: ROR + XOR + Modular Arithmetic

---

## 📄 Overview

This lab analyzes **algorithm_check**, a custom authentication binary that applies a **three-stage transformation pipeline** per byte to validate a 32-byte input token. The pipeline combines:

1. **Multiply-by-7** (via repeated `paddb` / `psubb` SIMD instructions)
2. **XOR 0x5A** (byte mask via `pxor` with broadcast constant)
3. **Right rotate 5 bits** (`psrlw xmm1, 5`)

Despite using 253 instructions and XMM SIMD operations, the transformation is **fully invertible** — a Python solver reconstructs the valid token statically.

---

## 📁 Report File

| File | Description |
|------|-------------|
| `Lab03_AlgorithmCheck_Security_Report.pdf` | Full professional security report (PDF format) |

---

## 🎯 Target Binary

| Property | Value |
|----------|-------|
| Binary Name | `algorithm_check` |
| Format | ELF 64-bit LSB Executable |
| Architecture | AMD x86-64 |
| Linkage | Dynamically linked |
| Kernel Requirement | GNU/Linux >= 4.4.0 |
| Entry Point | `0x004010a0` (fixed — PIE disabled) |
| Build ID (SHA1) | `04a49337734c768fdd03ddb691ae082fc76bb378` |
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

---

## 🔍 Findings Summary

| ID | Title | Component | Severity |
|----|-------|-----------|----------|
| **ALC-01** | Weak Binary Protections | Build config | 🟡 **MEDIUM** |
| **ALC-02** | Hardcoded Transform Constants in .rodata | `.rodata` @ `0x00402030` | 🟠 **HIGH** |
| **ALC-03** | Multi-Step Transform Fully Reversible | `fcn.004011b0` | 🔴 **CRITICAL** |

---

## 🔬 Vulnerability Details

### ALC-01 — Weak Binary Protections `MEDIUM`

Identical posture to Lab02: no stack canary, PIE disabled, partial RELRO only.

```bash
$ checksec file algorithm_check
Partial RELRO   No Canary Found   NO SHSTK & NO IBT   NX enabled   PIE Disabled
```

---

### ALC-02 — Hardcoded Transform Constants in .rodata `HIGH`

All 32 target bytes are stored verbatim at `.rodata`:

```bash
[0x004011b0]> px 16 @ 0x402030
0x00402030  9e21 4b67 9812 4388 115a 7e19 6391 7255

[0x004011b0]> px 16 @ 0x402040
0x00402040  2849 3f84 9120 6617 9340 187a 326e 5104
```

---

### ALC-03 — Multi-Step Transform Fully Reversible `CRITICAL`

**fcn.004011b0** (253 instructions) applies per-byte:

```
Step 1: multiply by 7  (paddb × repeated adds)
Step 2: XOR 0x5A       (pxor xmm1, xmm6 — broadcast 0x5a5a5a5a)
Step 3: ROR 5 bits     (psrlw xmm1, 5)
```

Each step is individually invertible:

| Forward | Inverse |
|---------|---------|
| `× 7 mod 256` | `× INV7 (183) mod 256` — since `7 × 183 ≡ 1 mod 256` |
| `XOR 0x5A` | `XOR 0x5A` — XOR is self-inverse |
| `ROR 5` | `ROL 3` — `(8-5)=3` left rotate |

**Python Solver (solve.py):**

```python
import sys

# Extracted from: r2 px 32 @ 0x402030
target = [
    0x9e,0x21,0x4b,0x67, 0x98,0x12,0x43,0x88,
    0x11,0x5a,0x7e,0x19, 0x63,0x91,0x72,0x55,
    0x28,0x49,0x3f,0x84, 0x91,0x20,0x66,0x17,
    0x93,0x40,0x18,0x7a, 0x32,0x6e,0x51,0x04,
]

INV7 = 183  # 7 * 183 ≡ 1 (mod 256)

def ror(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xff

result = []
for t in target:
    x = ror(t, 3)              # inverse of ROR 5 = ROL 3
    x ^= 0x5A                  # XOR self-inverse
    x = ((x - 3) * INV7) & 0xff  # modular multiplicative inverse
    result.append(x)

sys.stdout.buffer.write(bytes(result))
```

**Exploitation:**

```bash
$ python3 solve.py | ./algorithm_check
ACCESS GRANTED

# No brute force. No GDB. No runtime execution.
# Pure static analysis + modular arithmetic.
```

---

## 🧠 Algorithm Architecture

```
Input (32 bytes via fread → stdin)
          │
          ▼
  fcn.004011b0 — 253-instruction Transform
  ┌──────────────────────────────────────────┐
  │  Load constants: 0x30303030, 0x5a5a5a5a  │
  │  Load targets:   movdqa xmm0,[0x402030]  │  ← .rodata block 1
  │                  movdqa xmm0,[0x402040]  │  ← .rodata block 2
  │  Per-byte loop:                          │
  │    paddb × 3 → psubb               ×7   │  step 1: multiply
  │    pxor xmm1, xmm6                 0x5A │  step 2: XOR mask
  │    psrlw xmm1, 5                   ROR5 │  step 3: rotate
  │  cmp rax, 0x20 → jne (loop 32B)        │
  └──────────────────────────────────────────┘
          │
    test eax, eax
    ┌─────┴──────┐
    ▼            ▼
ACCESS GRANTED  ACCESS DENIED
```

---

## 🔑 Key Math: Modular Inverse

```
7 × 183 = 1281
1281 mod 256 = 1  ✓

Therefore: if y = (x * 7) mod 256
Then:      x = (y * 183) mod 256
```

---

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Binary format identification |
| `checksec` | Exploit mitigation survey |
| `strings` | `ACCESS GRANTED` / `ACCESS DENIED` leak |
| `r2 / Radare2` | Full static analysis framework |
| `r2: afl` | fcn.004011b0 = 253 instructions |
| `r2: pdf @ 0x4011b0` | XMM transform disassembly |
| `r2: px 32 @ 0x402030` | Extract target constants |
| `python3 solve.py` | Token reconstruction via inverse algebra |

---

## ✅ Recommendations

- **Replace custom transform** with HMAC-SHA256 or asymmetric crypto
- **Never store transform targets in .rodata** — use remote validation
- **Enable PIE**: `-fPIE -pie`
- **Enable Stack Canary**: `-fstack-protector-strong`
- **Enable Full RELRO**: `-Wl,-z,relro,-z,now`

---

## 📊 Lab Progression

| Lab | Binary | Algorithm | Bypass Method | Difficulty |
|-----|--------|-----------|---------------|-----------|
| Lab01 | secure_boot_validator | Single `test al,al` | GDB / byte patch | Easy |
| Lab02 | encoded_authenticator | XOR symmetric | Python XOR inversion | Medium |
| Lab03 | algorithm_check | ROR + XOR + ModMul | Python inverse algebra | Hard |

---

## ⚠️ Disclaimer

All content produced solely for educational and authorized security research purposes within the SafeTest-Dev lab framework.

---

## 👤 Author

**Michael.A** — SafeTest-Dev | Binary Security Research
Report Date: March 2026 | Classification: Confidential – Authorized Use Only

---

*SafeTest-Dev | Binary | Reverse | Malware | AI*
