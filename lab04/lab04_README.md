# 🟣 Lab04 — Reverse Engineering: Binary Patching

> **SafeTest-Dev | Reverse Engineering Portfolio**
> Static analysis dan binary patching pada PE32+ Windows executable menggunakan Radare2.

---

## 📋 Lab Overview

| Field | Detail |
|-------|--------|
| **Binary** | `loader.exe` |
| **Format** | PE32+ · x86-64 · Stripped to external PDB · 10 Sections |
| **OS Target** | MS Windows 5.02 (console) |
| **Platform Analisis** | Arch Linux + Wine |
| **Tool Utama** | Radare2 (r2) |
| **Teknik** | Static Analysis + Binary Patching (NOP Injection) |
| **Difficulty** | ⭐⭐⭐☆☆ Intermediate |
| **Flag** | `FLAG{STAGE1_PASS}` |

---

## 🎯 Objektif

1. Identifikasi format binary PE32+ menggunakan `file`
2. Eksekusi awal via `wine` — observasi perilaku runtime
3. Analisis statis dengan Radare2 — pemetaan fungsi, disassembly, cross-reference
4. Temukan lokasi validasi key: `strcmp` → `test eax` → `JNE` di `fcn.140002b00`
5. Binary patching: ganti `JNE` dengan `NOP NOP` di `0x140002bad–0x140002bae`
6. Verifikasi bypass → `[+] Access granted` + `FLAG{STAGE1_PASS}`

---

## 🧭 Metodologi

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
       jne  0x140002bf2    <- TARGET PATCH (opcode: 75 43)

6. BINARY PATCHING
   └── s 0x140002bad -> oo+ -> wa nop  (75 -> 90)
   └── s 0x140002bae -> wa nop         (43 -> 90)
   └── pd 3 -> [90 nop][90 nop][lea rcx, str.Access_granted] OK

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
0x140002bad    call strcmp(s1, s2)        ; compare
0x140002bad    test eax, eax             ; 0 = match
0x140002bad    jne  0x140002bf2          ; <- TARGET -- jump to Wrong key

; -- After NOP Patch -----------------------------------------------------------

0x140002bad    90    nop                 ; was: 75 (JNE opcode)
0x140002bae    90    nop                 ; was: 43 (JNE offset)
0x140002baf    lea rcx, str.Access_granted  ; falls through -> ACCESS GRANTED
```

**2 byte diubah (75 43 -> 90 90) — bypass key validation sepenuhnya.**

---

## 📊 Before vs After

| | Sebelum Patch | Setelah Patch |
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
| ALC-01 | Stripped Binary — No Debug Symbols | MEDIUM |
| ALC-02 | Key Validation Visible in Plain Disassembly | HIGH |
| ALC-03 | Multi-Step Bypass Fully Achievable via NOP Injection | CRITICAL |

---

## 🛠️ Commands Cheatsheet

```bash
# Identifikasi binary
file loader.exe

# Jalankan via Wine
wine loader.exe run

# Buka di Radare2 - full analysis
r2 -A loader.exe

# Di dalam r2:
afl                      # list semua fungsi
s fcn.140001010          # seek ke main
pdf                      # disassembly fungsi
s fcn.140002b00          # seek ke validator
s 0x140002bad            # seek ke alamat JNE
oo+                      # aktifkan write mode
wa nop                   # patch byte pertama -> NOP (0x90)
s 0x140002bae            # byte kedua JNE
wa nop                   # patch byte kedua  -> NOP (0x90)
pd 3                     # verifikasi patch
q                        # quit
```

---

## 🛡️ Defensive Recommendations

| # | Rekomendasi | Dampak |
|---|-------------|--------|
| 1 | Code signing + integrity check pada binary | Deteksi modifikasi sebelum eksekusi |
| 2 | Validasi key server-side, bukan lokal | Eliminasi attack surface patching |
| 3 | Obfuscation pada logika validasi | Persulit identifikasi target via disasm |
| 4 | Anti-debug / anti-tamper layer | Deteksi environment analisis |
| 5 | Packer / VM protection (VMProtect, Themida) | Obfuscasi tingkat binary |

---

## 📁 Repository Structure

```
lab04/
├── loader.exe                                 # Binary target (original)
├── loader_patched.exe                         # Binary hasil patch
├── lab04_reverse_engineering_dokumentasi.pdf  # Full report PDF
├── README.md                                  # This file
└── carousel/
    ├── lab04_carousel_1.png                   # Binary Check
    ├── lab04_carousel_2.png                   # Reconnaissance
    ├── lab04_carousel_3.png                   # Static Analysis
    ├── lab04_carousel_4.png                   # Key Finding
    ├── lab04_carousel_5.png                   # Binary Patching
    └── lab04_carousel_6.png                   # Findings & Result
```

---

## 🔗 Series Progression

```
RE-01  [ PE32+ · Stripped · NOP Patch ]  ->  strcmp bypass -> Access granted
RE-02  [ coming soon ]
RE-03  [ coming soon ]
```

---

## ⚠️ Disclaimer

All content in this repository is created **solely for defensive security research, threat intelligence,
and educational purposes** under the SafeTest-Dev binary security research framework.

- All analysis performed in isolated environment (Arch Linux + Wine)
- All techniques documented for defensive understanding and incident response
- Do NOT apply these techniques to systems without explicit written authorization

---

## 👤 Author

**Michael.A** — SafeTest-Dev
Binary · Reverse · Malware · Exploitation · AI

*SafeTest-Dev © 2026 — All rights reserved*
