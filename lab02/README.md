# 🔬 Lab02 — Encoded Authenticator

> **SafeTest-Dev | Binary Security Research**  
> XOR-Encoded Authentication Bypass via Static & Dynamic Analysis

---

## 📋 Lab Overview

| Field | Details |
|-------|---------|
| **Target Binary** | `encoded_authenticator` |
| **Binary Type** | ELF 64-bit LSB Executable, x86-64 |
| **Linking** | Dynamically linked |
| **Symbols** | Stripped |
| **Interpreter** | `/lib64/ld-linux-x86-64.so.2` |
| **BuildID (SHA1)** | `469cedd4d764d7133b430902dd308420bbfdae71` |
| **Compiled For** | GNU/Linux 4.4.0 |
| **Vulnerability** | XOR-Encoded Token Bypass |
| **Severity** | 🔴 **Critical** |
| **Technique** | Static Disassembly (Radare2), XOR Decoding, Python Solver |

---

## 🎯 Objective

Reverse engineer a stripped ELF binary that performs XOR-encoded authentication. Identify the encoded token stored in the `.rodata` section, recover the XOR key, and construct a solver to bypass the authentication check without modifying the binary.

---

## 🔍 Methodology

### Phase 1 — Reconnaissance (`file`, `strings`, `tee`)

```bash
file encoded_authenticator \
  | sed 's/,/\n/g' \
  | sed 's/^ *//' \
  | tee output/file_metadata.txt
```

**Output:**
```
encoded_authenticator: ELF 64-bit LSB executable
x86-64
version 1 (SYSV)
dynamically linked
interpreter /lib64/ld-linux-x86-64.so.2
BuildID[sha1]=469cedd4d764d7133b430902dd308420bbfdae71
for GNU/Linux 4.4.0
stripped
```

**Strings analysis** revealed imported functions (`puts`, `fread`, `stdin`) and ELF section names (`.text`, `.rodata`, `.data`, `.bss`, `.got`, `.got.plt`) — confirming the binary uses standard libc I/O. Notably, no hardcoded password strings are visible, indicating encoding/obfuscation of the secret token.

---

### Phase 2 — Security Mitigations (`checksec`)

```bash
checksec file encoded_authenticator
```

| Mitigation | Status |
|------------|--------|
| **RELRO** | Partial RELRO |
| **Stack Canary** | ❌ No Canary Found |
| **CFI / SHSTK** | ❌ NO SHSTK & NO IBT |
| **NX** | ✅ NX enabled |
| **PIE** | ❌ PIE Disabled |
| **FORTIFY** | ❌ No |
| **Symbols** | ❌ Stripped |

**Assessment:** The binary has minimal exploit mitigations. No stack canary and no PIE make it vulnerable to stack-based exploits. However, the primary vulnerability here is logical — XOR-encoded token comparison without key protection.

---

### Phase 3 — Static Analysis (`radare2`)

#### 3.1 — Full Analysis Pass

```bash
r2 encoded_authenticator
[0x004010a0]> aaa
```

Radare2 performed complete analysis including: imports, entrypoint, symbols, function arguments/locals, function calls, and C++ vtables.

#### 3.2 — Function Listing (`afl`)

```
Address       Calls  Size  Function
0x00401030    1      6     sym.imp.puts
0x00401040    1      6     sym.imp.fread
0x004010a0    1      37    entry0
0x00401050    4      76    main
0x00401230    3      144   fcn.00401230       ← XOR decode routine
0x00401180    5      57    entry.init0
0x00401150    3      32    entry.fini0
0x004010e0    4      33    fcn.004010e0
```

**Key observation:** `fcn.00401230` (144 bytes, 3 basic blocks) is called from `main` at `0x401071` — this is the XOR decode/comparison routine.

#### 3.3 — Main Function Disassembly (`pdf @ main`)

```
76: int main (int argc, char **argv, char **envp);
0x00401050    push rbx
0x00401051    mov edx, 0x20          ; size_t nmemb = 32
0x00401056    mov esi, 1             ; size_t size = 1
0x0040105b    sub rsp, 0x20
0x0040105f    mov rcx, qword [obj.stdin]  ; FILE *stream
0x00401066    mov rdi, rsp           ; void *ptr
0x00401069    call sym.imp.fread     ; reads 32 bytes from stdin
0x0040106e    mov rdi, rsp
0x00401071    call fcn.00401230      ← decode + compare
0x00401076    test eax, eax
0x00401078    jne 0x40108e           ; branch if NO
0x0040107a    lea rdi, [0x00402004]  ; "OK"
0x00401081    call sym.imp.puts
0x00401086    add rsp, 0x20
0x0040108a    xor eax, eax
0x0040108c    ret
0x0040108e    lea rdi, [0x00402007]  ; "NO"
0x00401095    call sym.imp.puts
0x0040109a    jmp 0x401086
```

**Logic flow:** `fread` reads 32 bytes from `stdin` → `fcn.00401230` XOR-decodes stored token and compares with input → outputs `OK` or `NO`.

#### 3.4 — XOR Decode Routine (`pdf @ 0x00401230`)

```
144: fcn.00401230 (int64_t arg1);
0x00401230    pxor xmm2, xmm2
0x00401234    pxor xmm4, xmm4
0x00401238    pxor xmm3, xmm3
0x0040123c    xor eax, eax
0x0040123e    movdqa xmm0, xmmword [0x00402030]  ← encoded token (16 bytes)
0x00401246    movaps [rsp - 0x28], xmm0
0x0040124b    movdqa xmm0, xmmword [0x00402040]  ← encoded token (16 bytes)
0x00401253    movaps [rsp - 0x18], xmm0
; Loop: XOR decode 16-byte chunks against input
0x00401258    movdqu xmm0, xmmword [rdi + rax]   ; input chunk
0x0040125d    pxor xmm0, xmmword [rsp + rax - 0x28]  ; XOR with encoded
0x00401263    add rax, 0x10                       ; advance 16 bytes
0x00401267    movdqa xmm1, xmm0
; ... SIMD byte shuffle/reduction to compare result ...
0x004012bf    ret
```

The routine loads 32 bytes of encoded data from `0x402030–0x40204F`, XORs them against the 32-byte input, then checks if the result is zero (i.e., input == decoded token).

#### 3.5 — Encoded Token Dump (`px 32 @ 0x402030`)

```
- offset -  3031 3233 3435 3637 3839 3A3B 3C3D 3E3F  0123456789ABCDEF
0x00402030  7909 e4b4 2af1 eaed d2aa d9ce d39e 1f71  y...*..........q
0x00402040  e2e7 2185 18bf 1fb5 c729 5f36 87f2 a5df  ..!.......)_6....
```

This is the XOR-encoded 32-byte secret stored in `.rodata`.

---

### Phase 4 — Exploitation (Python Solver)

With the encoded bytes recovered, a Python solver constructs the correct payload by reversing the XOR operation using the known key structure identified from the SIMD decode routine:

```python
import sys

payload = bytes([
    0x79, 0x09, 0xe4, 0xb4, 0x2a, 0xf1, 0xea, 0xed,
    0xd2, 0xaa, 0xd9, 0xce, 0xd3, 0x9e, 0x1f, 0x71,
    0xe2, 0xe7, 0x21, 0x85, 0x18, 0xbf, 0x1f, 0xb5,
    0xc7, 0x29, 0x5f, 0x36, 0x87, 0xf2, 0xa5, 0xdf
])

sys.stdout.buffer.write(payload)
```

**Execution:**

```bash
python3 python_solver.py | ./encoded_authenticator
OK
```

Authentication bypassed successfully. ✅

---

## 📁 Repository Structure

```
lab02/
├── encoded_authenticator          # Target binary (ELF 64-bit)
├── python_solver.py               # Exploit — XOR payload solver
├── output/
│   ├── file_metadata.txt          # file command output
│   ├── checksec.json              # Security mitigations report
│   ├── strings_output.txt         # strings analysis
│   ├── r2_functions.txt           # afl — function listing (radare2)
│   ├── r2_main_disasm.txt         # pdf @ main disassembly
│   ├── r2_fcn_disasm.txt          # pdf @ 0x00401230 XOR routine
│   └── r2_encoded_bytes.txt       # px 32 @ 0x402030 — encoded token
├── README.md                      ← You are here
└── Lab02_EncodedAuthenticator_Security_Report.docx
```

---

## 🛠️ Tools Used

| Category | Tool | Usage |
|----------|------|-------|
| Identification | `file` | Binary type detection |
| Strings | `strings` | Import & section enumeration |
| Mitigations | `checksec` | Security feature audit |
| Disassembly | `radare2` (`r2`) | Full static disassembly & analysis |
| Memory Inspection | `px` (radare2) | Raw byte dump of encoded token |
| Exploitation | `python3` | XOR payload construction |

---

## 🔑 Findings Summary

| # | Finding | Severity |
|---|---------|----------|
| 1 | No PIE — fixed binary base address | 🟠 High |
| 2 | No stack canary — stack overflow possible | 🟠 High |
| 3 | XOR-encoded token in `.rodata` — trivially recoverable | 🔴 Critical |
| 4 | No key protection — XOR key embedded in function logic | 🔴 Critical |
| 5 | Authentication bypassable with static analysis alone | 🔴 Critical |

---

## 🛡️ Recommendations

- **Replace static XOR** with a proper cryptographic HMAC or challenge-response scheme
- **Enable PIE** (`-fPIE -pie`) to randomize the base address at runtime
- **Enable Stack Canary** (`-fstack-protector-strong`) to prevent stack-based overflows
- **Enable Full RELRO** (`-Wl,-z,relro,-z,now`) to make the GOT read-only
- **Avoid storing secrets in `.rodata`** — use secure enclaves or runtime key derivation

---

## ⚠️ Disclaimer

All content in this lab is created **solely for educational and authorized security research purposes** under the SafeTest-Dev lab framework. The binary analyzed is a purpose-built lab sample.

---

**Author:** Michael.A — SafeTest-Dev  
*Binary | Reverse | Malware | AI*

*SafeTest-Dev © 2026 — All rights reserved*
