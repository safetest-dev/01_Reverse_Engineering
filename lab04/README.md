# 🟣 Lab04 — Reverse Engineering: Binary Patching

> **SafeTest-Dev | Reverse Engineering Portfolio**
> Static analysis and binary patching on a PE32+ Windows executable using Radare2.

---

## 📋 Lab Overview

| Field | Detail |
|-------|--------|
| **Binary** | `loader.exe` |
| **Format** | PE32+ · x86-64 · Stripped to external PDB · 10 Sections |
| **OS Target** | MS Windows 5.02 (console) |
| **Analysis Platform** | Arch Linux + Wine |
| **Primary Tool** | Radare2 (r2) |
| **Technique** | Static Analysis + Binary Patching (NOP Injection) |
| **Difficulty** | ⭐⭐⭐☆☆ Intermediate |
| **Flag** | `FLAG{STAGE1_PASS}` |

---

## 🧭 Methodology

```
1. IDENTIFICATION
   └── file loader.exe
       PE32+ executable · x86-64 · stripped to external PDB · 10 sections

2. DYNAMIC PREVIEW
   └── wine loader.exe run
       == Secure Loader v2.1 ==
       Enter key: trial_key_random
       [-] Wrong key

3. STATIC ANALYSIS
   └── r2 -A loader.exe
       INFO: Analyze all flags (aa)
       INFO: Analyze imports / entrypoint / symbols
       INFO: Analyze function calls / locals / types

4. FUNCTION MAPPING
   └── afl
       0x140001400   entry0              (29 instr)
       0x140001010   fcn.140001010       (967 instr -- MAIN)
       0x1400028c0   fcn.1400028c0       (11 instr  -- key getter)
       0x140002b00   fcn.140002b00       (310 instr  -- VALIDATOR)

5. KEY FINDING
   └── fcn.140002b00 @ 0x140002bad
       call strcmp(s1, s2)
       test eax, eax
       jne  0x140002bf2    <- PATCH TARGET (opcode: 75 43)

6. BINARY PATCHING
   └── s 0x140002bad -> oo+ -> wa nop  (75 -> 90)
   └── s 0x140002bae -> wa nop         (43 -> 90)
   └── pd 3 -> [90 nop][90 nop][lea rcx, str.Access_granted]  OK

7. VERIFICATION
   └── wine loader.exe run
       Enter key: randomkeyfortest
       [+] Access granted
       FLAG{STAGE1_PASS}
```

---

## 🔑 Key Finding — Disassembly

```asm
; -- fcn.140002b00 -- Key Validation Function ----------------------------------

0x140002b97    call scanf()               ; read user input -> s1
0x140002ba1    lea rcx, [s1]             ; user input ptr
0x140002b9c    lea rdx, [s2]             ; correct key ptr
0x140002bad    call strcmp(s1, s2)        ; compare input vs correct key
0x140002bad    test eax, eax             ; 0 = match, non-zero = mismatch
0x140002bad    jne  0x140002bf2          ; <- PATCH TARGET -- jumps to Wrong key

; -- After NOP Patch -----------------------------------------------------------

0x140002bad    90    nop                 ; was: 75 (JNE opcode)
0x140002bae    90    nop                 ; was: 43 (JNE offset)
0x140002baf    lea rcx, str.Access_granted  ; falls through -> ACCESS GRANTED
```

**Only 2 bytes changed (75 43 -> 90 90) — key validation fully bypassed.**

---

## 📊 Before vs After

| | Before Patch | After Patch |
|--|--|--|
| **Input** | `randomkeyfortest` | `randomkeyfortest` |
| **Output** | `[-] Wrong key` | `[+] Access granted` |
| **Flag** | ❌ | `FLAG{STAGE1_PASS}` ✅ |
| **Byte @ 0x140002bad** | `75` (JNE opcode) | `90` (NOP) |
| **Byte @ 0x140002bae** | `43` (JNE offset) | `90` (NOP) |

---

## 🔍 Findings Summary

| ID | Title | Severity |
|----|-------|----------|
| ALC-01 | Stripped Binary — No Debug Symbols | 🟡 MEDIUM |
| ALC-02 | Key Validation Visible in Plain Disassembly | 🟠 HIGH |
| ALC-03 | Multi-Step Bypass Fully Achievable via NOP Injection | 🔴 CRITICAL |

### ALC-01 — Stripped Binary

The binary has been stripped to an external PDB — no function names or debug symbols are present in the file itself. All functions appear as `fcn.xxxxxxxxx` in Radare2. While this raises the analysis bar slightly, it does not prevent identification of the validation logic through disassembly pattern recognition.

### ALC-02 — Key Validation in Plain Disassembly

The complete key validation flow is visible in static disassembly without any obfuscation. The `strcmp` call, `test eax`, and the `JNE` branch are all clearly identifiable in `fcn.140002b00`. An attacker requires no dynamic execution to locate the patch target — static analysis alone is sufficient.

### ALC-03 — Multi-Step Bypass via NOP Injection *(Critical)*

The multi-step transform is fully reversible through static analysis. The patch requires modifying only 2 bytes at a known static address (`0x140002bad`):

```
oo+                      ; enable write mode
wa nop @ 0x140002bad     ; 75 -> 90
wa nop @ 0x140002bae     ; 43 -> 90
```

Result: CPU no longer jumps to the "Wrong key" block regardless of key input.
Output: `[+] Access granted` + `FLAG{STAGE1_PASS}`.

---

## 🛠️ Commands Cheatsheet

```bash
# Identify binary format
file loader.exe

# Execute via Wine
wine loader.exe run

# Open in Radare2 — full analysis
r2 -A loader.exe

# Inside r2:
afl                      # list all identified functions
s fcn.140002b00          # seek to validator function
pdf                      # print disassembly
s 0x140002bad            # seek to JNE address
oo+                      # enable read-write mode
wa nop                   # patch first byte  -> NOP (0x90)
s 0x140002bae            # seek to second byte
wa nop                   # patch second byte -> NOP (0x90)
pd 3                     # verify patch result
```

---

## 🛡️ Defensive Recommendations

| # | Recommendation | Impact |
|---|----------------|--------|
| 1 | Code signing + integrity check on the binary | Detect any modification before execution |
| 2 | Server-side key validation instead of local | Eliminate binary patching as an attack surface entirely |
| 3 | Obfuscation of validation logic | Make patch target identification significantly harder |
| 4 | Anti-debug / anti-tamper layer | Detect analysis environment at runtime |
| 5 | Packer / VM protection (VMProtect, Themida) | Binary-level obfuscation against static analysis |

---

## ⚠️ Disclaimer

All content in this repository is created **solely for defensive security research, threat intelligence,
and educational purposes** under the SafeTest-Dev binary security research framework.

- All analysis performed in an isolated environment (Arch Linux + Wine)
- All techniques documented for defensive understanding and incident response
- Do **NOT** apply these techniques to systems without explicit written authorization

---

## 👤 Author

**Michael.A** — SafeTest-Dev
Binary · Reverse · Malware · Exploitation · AI

*SafeTest-Dev © 2026 — All rights reserved*
