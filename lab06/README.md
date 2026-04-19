# 🟠 Lab06 — Reverse Engineering: DLL Hijacking & Control Flow Manipulation

> **SafeTest-Dev | Reverse Engineering Portfolio**
> Control flow manipulation and string patching on a real-world PE32+ Windows installer — Notepad++ v8.9.3.

---

## 📋 Lab Overview

| Field | Detail |
|-------|--------|
| **Binary** | `npp.8.9.3.Installer.x64.exe` (Notepad++ v8.9.3 official installer) |
| **Format** | PE32+ · x86-64 · Windows Installer · NSIS-based |
| **Analysis Platform** | Arch Linux + Wine |
| **Primary Tools** | Radare2 (r2) · vim · wine |
| **Technique** | Static Analysis + Control Flow Manipulation + String Patching |
| **Difficulty** | ⭐⭐⭐⭐☆ Advanced |
| **POC Result** | `POC-1 GOT IT` displayed in NSIS error dialog |

---

## 🎯 Objectives

1. Identify and run the installer normally via Wine — observe standard behavior
2. Perform full static analysis with `r2 -A` — map functions and string references
3. Locate the integrity check branch at `0x0040337f` (`je` → error block)
4. Patch control flow: redirect `je` → `jmp 0x004030fc` to bypass the error path
5. Locate the NSIS Error string at `0x0040a098` in the .data section
6. Overwrite the string with `"POC-1 GOT IT"` using UTF-16LE encoding via `wx`
7. Verify both patches — NSIS dialog confirms `POC-1 GOT IT`

---

## 🧭 Methodology

```
1. IDENTIFICATION
   └── ls ~/init
       NppConverter.dll  NppExport.dll  mimeTools.dll
       notepad++.exe     npp.8.9.3.Installer.x64.exe

2. NORMAL EXECUTION
   └── wine npp.8.9.3.Installer.x64.exe
       -> Notepad++ v8.9.3 Setup GUI launches
       -> Installation completes successfully
       -> changelog.log opens post-install (CVE-2025-14819 noted)

3. STATIC ANALYSIS
   └── r2 -A npp.8.9.3.Installer.x64.exe
       entry0         -> 1565 instr
       fcn.00401434   ->  887 instr  (main NSIS runtime)
       fcn.004068a    ->  175 instr  (integrity check region)
       fcn.004033d0   ->  264 instr  (CRC computation)

4. STRING MAPPING (vim visual mode)
   └── 0x00008020  -> "verifying installer: %d%%" (UTF-16)
   └── 0x0040a098  -> NSIS Error message           <- PATCH TARGET

5. CONTROL FLOW PATCH
   └── 0x0040337f  je  0x00403388   (original — CRC match branch)
   └── PATCH:  oo+ -> wa jmp 0x004030fc  -> wx eb7b
   └── Effect: integrity check error path bypassed unconditionally

6. STRING PATCH
   └── s 0x0040a098 -> oo+ -> wx 50004f0043002d003100204f004f005400490054000000
   └── psu -> "POC-1 GOT IT"  <- confirmed

7. VERIFICATION
   └── wine npp.8.9.3.Installer.x64.exe (patched)
       -> NSIS error dialog appears
       -> Dialog displays: "POC-1 GOT IT"  <- POC confirmed
```

---

## 🔑 Key Finding 1 — Control Flow Patch

```asm
; -- Integrity check branch @ 0x0040337f ----------------------------------

0x00403376    call fcn.004033d0         ; compute CRC of installer
0x0040337c    cmp eax, dword [dwBytes]  ; compare against expected CRC

; ORIGINAL -- jumps to "CRC OK" path if match
0x0040337f    je   0x00403388           ; opcode: 74 07

; NEXT INSTRUCTION if CRC fails -> loads NSIS error string
0x00403381    mov eax, str.NSIS_Error   ; "Installer integrity check has failed..."

; PATCHED -- unconditional jump, bypasses error block entirely
0x0040337f    jmp  0x004030fc           ; opcode: eb 7b  <- 2 bytes written
```

**2 bytes changed (74 07 → eb 7b) — integrity check fully bypassed.**

---

## 🔑 Key Finding 2 — String Patch (UTF-16LE)

```bash
# Seek to NSIS error string
[0x0040a098]> s 0x0040a098

# Inspect original (UTF-16LE)
[0x0040a098]> psu
# -> "Installer integrity check has failed. Common causes include..."

# Enable write mode
[0x0040a098]> oo+

# Write "POC-1 GOT IT" as UTF-16LE + null terminator
[0x0040a098]> wx 50004f0043002d003100204f004f005400490054000000

# Verify
[0x0040a098]> psu
# -> "POC-1 GOT IT"  <- confirmed
```

**UTF-16LE encoding — each ASCII character = 2 bytes (char + 0x00):**

| P | O | C | - | 1 | (sp) | G | O | T | (sp) | I | T |
|---|---|---|---|---|------|---|---|---|------|---|---|
| `50 00` | `4f 00` | `43 00` | `2d 00` | `31 00` | `20 00` | `47 00` | `4f 00` | `54 00` | `20 00` | `49 00` | `54 00` |

---

## 🔍 Findings Summary

| ID | Title | Severity |
|----|-------|----------|
| ALC-01 | Integrity Check Bypassable via 2-Byte Jump Redirect | 🔴 CRITICAL |
| ALC-02 | NSIS Error String Overwritable in .data Section | 🟠 HIGH |
| ALC-03 | Real-World Production Binary — Same Attack Surface | 🟠 HIGH |

### ALC-01 — Integrity Check Bypass *(Critical)*

The NSIS installer's integrity check feeds into a single `je` instruction at `0x0040337f`. Redirecting this to an unconditional `jmp` bypasses the entire error path with just 2 bytes written. An attacker who can modify the binary can trivially defeat the CRC check — making the integrity protection ineffective against targeted tampering.

### ALC-02 — UTF-16LE String Overwrite *(High)*

The NSIS error message is stored as a UTF-16LE wide string in the writable `.data` section at a static address (`0x0040a098`). No ASLR means the address is predictable across every run. An attacker can overwrite this with arbitrary content — enabling social engineering via misleading installer dialogs.

### ALC-03 — Real-World Software *(High)*

Unlike previous labs using purpose-built CTF binaries, Lab06 confirms the same static analysis and binary patching workflow applies directly to production software. The Notepad++ v8.9.3 official installer provides no additional resistance to `r2`-based patching beyond the integrity check — which is trivially bypassed by ALC-01.

---

## 🛠️ Commands Reference

```bash
# Run installer via Wine (normal)
wine npp.8.9.3.Installer.x64.exe

# Open in Radare2 — full analysis
r2 -A npp.8.9.3.Installer.x64.exe

# Inside r2:
afl                          # list all functions
s 0x0040337f                 # seek to integrity check jump
oo+                          # enable write mode
wa jmp 0x004030fc            # redirect jump (control flow patch)
wx eb7b                      # alternative: write bytes directly

s 0x0040a098                 # seek to NSIS error string
psu                          # print UTF-16LE string (inspect)
wx 50004f0043002d003100204f004f005400490054000000   # write "POC-1 GOT IT"
psu                          # verify patched string
```

---

## 🛡️ Defensive Recommendations

| # | Recommendation | Impact |
|---|----------------|--------|
| 1 | Multi-point integrity checks — not a single CRC jump | Eliminates single-point bypass |
| 2 | Digital code signing + runtime signature verification | Detects any binary modification |
| 3 | Enable PIE/ASLR on the installer binary | Prevents static address targeting |
| 4 | Store UI strings in read-only `.rdata` — not writable `.data` | Prevents string overwrite attacks |
| 5 | Self-integrity hash verification of `.text` section at runtime | Detects code section tampering |

---

## ⚠️ Disclaimer

All content in this repository is created **solely for defensive security research, threat intelligence,
and educational purposes** under the SafeTest-Dev binary security research framework.

- All analysis performed in an isolated lab environment (Arch Linux + Wine)
- All techniques documented for defensive understanding and incident response
- Do **NOT** apply these techniques to software outside of a controlled lab environment

---

## 👤 Author

**Michael.A** — SafeTest-Dev
Binary · Reverse · Malware · Exploitation · AI

*SafeTest-Dev © 2026 — All rights reserved*
