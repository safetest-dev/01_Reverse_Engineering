# 🔵 Lab05 — Reverse Engineering: DLL Key XOR Decoding

> **SafeTest-Dev | Reverse Engineering Portfolio**
> Two-stage key bypass on a PE32+ Windows binary — static disassembly of payload.dll and XOR brute force decoding using hexor.

---

## 📋 Lab Overview

| Field | Detail |
|-------|--------|
| **Binary** | `loader.exe` + `payload.dll` |
| **Format** | PE32+ · x86-64 · Stripped · Windows Binary |
| **Analysis Platform** | Arch Linux + Wine |
| **Primary Tools** | Radare2 (r2) · hexor (Crystal) |
| **Technique** | Static Disassembly + XOR Brute Force Decoding |
| **Difficulty** | ⭐⭐⭐⭐☆ Advanced |
| **Flags** | `FLAG{STAGE1_PASS}` + `FLAG{STAGE2_DLL_PASS}` |

---

## 🎯 Objectives

1. Re-execute the patched `loader.exe` — observe Stage 2 DLL key prompt
2. Analyze `payload.dll` with Radare2 — locate `sym.payload.dll_run`
3. Extract the XOR-encoded hex constant `0x335157414d5b53` from disassembly
4. Run `hexor --brute` to enumerate all 255 XOR key candidates
5. Identify the readable result: key `0x12` → `AI_SEC!`
6. Supply `AI_SEC!` as the DLL key → `FLAG{STAGE2_DLL_PASS}`

---

## 🧭 Methodology

```
1. STAGE 1 (from Lab04)
   └── wine loader.exe run
       Enter key: key123
       [+] Access granted
       FLAG{STAGE1_PASS}
       [*] Enter DLL key:  <- Stage 2 prompt appears

2. STATIC ANALYSIS — payload.dll
   └── r2 -A payload.dll
   └── afl  ->  sym.payload.dll_run (150 instr) <- target
   └── s sym.payload.dll_run -> pdf

3. KEY FINDING
   └── 0x1db60140c  movabs rax, 0x335157414d5b53
                    ; "S[MAWQ3"  <- XOR-encoded DLL key

4. XOR DECODE LOOP (from disassembly)
   └── 0x1db601440  xor eax, 0x12   ; XOR key = 0x12
   └── 0x1db60144f  jne 0x1db601440 ; loop until null byte

5. HEXOR BRUTE FORCE
   └── hexor 0x335157414d5b53 --brute
       [key 0x12] => AI_SEC!    <- MATCH

6. VERIFICATION
   └── wine loader.exe run
       Enter key: key123        -> FLAG{STAGE1_PASS}
       Enter DLL key: AI_SEC!   -> FLAG{STAGE2_DLL_PASS}
```

---

## 🔑 Key Finding — Disassembly

```asm
; -- sym.payload.dll_run @ 0x1db601400 ----------------------------------------

0x1db601405    lea rcx, str.__Enter_DLL_key:   ; "[*] Enter DLL key: "

; XOR-encoded key constant loaded directly into RAX
0x1db60140c    movabs rax, 0x335157414d5b53    ; "S[MAWQ3" <- encoded key

0x1db601416    mov qword [s2], rax             ; store encoded key

; XOR decode loop
0x1db601440    xor eax, 0x12                   ; XOR each byte with 0x12
0x1db601443    add rdx, 1
0x1db601447    mov byte [rdx - 1], al
0x1db60144a    movzx eax, byte [rdx]
0x1db60144d    test al, al
0x1db60144f    jne 0x1db601440                 ; loop until null byte

0x1db601451    lea rdx, [s2]                   ; decoded key
0x1db601456    lea rcx, [s1]                   ; user input
; -> strncmp(user_input, decoded_key)
```

---

## 🔧 hexor — XOR Decoder Tool (Crystal)

`hexor` is a purpose-built Crystal CLI tool for XOR analysis. Core logic:

```crystal
# Little-endian byte parsing
def parse_hex(input)
  bytes = hex_chars.each_slice(2).map { |p| p.join.to_i(16).to_u8 }
  bytes.reverse!  # little endian correction
end

# Single-byte XOR decode
def xor_decode(bytes, key)
  bytes.map { |b| (b ^ key).chr }.join
end

# Printability filter — >85% ASCII printable required
def readable?(s)
  s.count { |c| c.ord >= 32 && c.ord <= 126 } > s.size * 0.85
end

# Brute force all 255 keys
def brute_xor(bytes)
  (1..255).each do |k|
    decoded = xor_decode(bytes, k)
    puts "[key 0x#{k.to_s(16)}] => #{decoded}" if readable?(decoded)
  end
end
```

```bash
# Brute force
hexor 0x335157414d5b53 --brute
# [key 0x12] => AI_SEC!  <- match

# Manual decode
hexor 0x335157414d5b53 0x12
# [+] Result  : AI_SEC!
```

---

## 📊 XOR Verification — Byte by Byte

| Encoded | XOR Key | Result | Char |
|---------|---------|--------|------|
| `0x53`  | `0x12`  | `0x41` | `A`  |
| `0x5B`  | `0x12`  | `0x49` | `I`  |
| `0x4D`  | `0x12`  | `0x5F` | `_`  |
| `0x41`  | `0x12`  | `0x53` | `S`  |
| `0x57`  | `0x12`  | `0x45` | `E`  |
| `0x51`  | `0x12`  | `0x43` | `C`  |
| `0x33`  | `0x12`  | `0x21` | `!`  |

---

## 🔍 Findings Summary

| ID | Title | Severity |
|----|-------|----------|
| ALC-01 | XOR-Encoded Key Stored as Hex Constant in .text Section | 🟠 HIGH |
| ALC-02 | Single-Byte XOR — Brute-Forceable in O(255) | 🔴 CRITICAL |
| ALC-03 | No Anti-Analysis Protection in DLL | 🟠 HIGH |

### ALC-01 — XOR-Encoded Constant in .text

The DLL key is embedded as a 7-byte XOR-encoded constant (`0x335157414d5b53`) via a `movabs` instruction at `0x1db60140c`. While this is marginally better than plaintext storage, it is immediately visible in static disassembly and requires no dynamic execution to extract.

### ALC-02 — Single-Byte XOR is O(255) *(Critical)*

Single-byte XOR has a keyspace of exactly 255 meaningful values. hexor exhausts the entire keyspace in a single pass. The printability filter (`>85% ASCII`) isolates `AI_SEC!` from noise automatically — no prior knowledge of the key required.

### ALC-03 — No Anti-Analysis in DLL

The DLL contains no anti-debug, anti-tamper, or obfuscation. The XOR loop is plainly visible in static disassembly at `0x1db601440–0x1db60144f`, and the XOR constant `0x12` is hardcoded with no dynamic resolution.

---

## 🛡️ Defensive Recommendations

| # | Recommendation | Impact |
|---|----------------|--------|
| 1 | Replace single-byte XOR with AES — eliminates brute force feasibility | High |
| 2 | Derive keys at runtime — never hardcode as a static hex constant | High |
| 3 | Add anti-debug / Wine detection to DLL | Medium |
| 4 | Verify DLL integrity before loading (signature / hash check) | High |
| 5 | Apply obfuscation or packer to DLL payload | Medium |

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

---

## ⚙️ hexor — Installation & Setup

### 1. Install Crystal

```bash
# Arch Linux
sudo pacman -S crystal

# Ubuntu / Debian
curl -fsSL https://crystal-lang.org/install.sh | sudo bash
sudo apt install crystal

# macOS
brew install crystal

# Verify installation
crystal --version
```

### 2. Compile hexor.cr

```bash
# Clone or download hexor.cr, then compile
crystal build hexor.cr --release -o hexor

# --release flag enables optimizations for faster execution
# -o hexor sets the output binary name
```

### 3. Run from Anywhere (Global Install)

```bash
# Move compiled binary to a directory in your PATH
sudo mv hexor /usr/local/bin/

# Verify it's accessible globally
which hexor
hexor --help

# Now you can run hexor from any directory
hexor 0x335157414d5b53 --brute
hexor 0x335157414d5b53 0x12
```

> **Note:** `/usr/local/bin` is already in `$PATH` on most Linux/macOS systems.
> On Arch Linux you can also use `~/.local/bin` — just make sure it's added to your `$PATH` in `~/.bashrc` or `~/.zshrc`.

```bash
# Alternative: add to user PATH (no sudo required)
mkdir -p ~/.local/bin
mv hexor ~/.local/bin/

# Add to shell config if not already there
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```
