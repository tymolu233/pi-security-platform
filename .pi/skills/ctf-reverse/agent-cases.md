# Agent Decision Cases

Worked examples showing the correct decision chain for RE agents. Each case shows what the agent sees, what it should do, and why AI models commonly get it wrong.

**When to load this file**: After triage, when you need guidance on a specific pattern. Do NOT read the entire file upfront.

---

## Case 1: Encryption Binary + .enc File

### What you see (triage output)

```
$ file target
target: ELF 64-bit LSB executable, x86-64, statically linked

$ strings target | grep -iE "key|encrypt|decrypt|enc|flag"
CCB_M4gic_K3y
/dev/urandom
%s.enc
encrypt_file
decrypt_file

$ ls workspace/targets/
target    flag.txt.enc
```

### Correct decision

```json
{
  "escalate_to": "crypto-analyst",
  "escalate_reason": "Binary encrypts files using key 'CCB_M4gic_K3y', companion flag.txt.enc exists. Crypto-analyst should determine algorithm (XOR/AES/custom) and decrypt.",
  "key_strings_found": ["CCB_M4gic_K3y", "%s.enc", "/dev/urandom"]
}
```

### Why AI models get this wrong

The model sees a key string and thinks "I can just XOR the file with this key." It then spends 30+ minutes writing Python scripts trying every combination (XOR, CBC, different key lengths, base64 variants). The problem: **the algorithm is unknown**. The key alone is not enough — you need to reverse the encryption function to know HOW the key is used (is it XOR? AES-CBC? Custom cipher with /dev/urandom as IV?).

### Rule

**Found key + found .enc file = escalate to crypto-analyst.** Never attempt decryption yourself. The crypto-analyst will ask re-static to decompile the encrypt function if needed.

---

## Case 2: IDA Decompile → z3 Translation

### What you see (IDA decompile output)

```c
int check_flag(char *input) {
  if (strlen(input) != 32) return 0;
  for (int i = 0; i < 32; i++) {
    if (((input[i] ^ 0x37) + i) % 256 != expected[i])
      return 0;
  }
  return 1;
}
```

### Correct action (write z3 solver)

```python
from z3 import *
s = Solver()
flag = [BitVec(f'f{i}', 8) for i in range(32)]
expected = [0x56, 0x7a, ...]  # from IDA: read expected array

for i in range(32):
    s.add(flag[i] >= 0x20, flag[i] <= 0x7e)  # printable
    s.add(((flag[i] ^ 0x37) + i) % 256 == expected[i])

if s.check() == sat:
    m = s.model()
    print(''.join(chr(m[flag[i]].as_long()) for i in range(32)))
```

### Why AI models get this wrong

1. They try angr first (overkill for a simple loop — angr path-explodes on string operations)
2. They forget to constrain to printable ASCII (get garbage solutions)
3. They use Python `int` instead of z3 `BitVec` (wrong modular arithmetic)
4. They don't extract the `expected` array from IDA (try to guess it)

### Rule

**Simple loop + byte comparison + known expected values = manual z3.** Always extract the expected array from IDA (`get_bytes` or `decompile` the data section). Don't use angr for < 50 lines of decompiled C.

---

## Case 3: Packed Binary (UPX fails)

### What you see

```
$ upx -t target
upx: target: NotPackedByUPX

$ strings target | grep UPX
$Info: This file is packed with the UPX executable packer
UPX!
```

### Correct decision

UPX magic is present but `upx -t` fails → **modified UPX header** (common anti-unpack trick).

**Fix sequence:**
1. Check section names: `rabin2 -S target | grep -i upx` — if renamed (e.g., `UPX0`→`ABC0`), restore them
2. Check UPX version bytes: `xxd target | grep "UPX!"` — if version field corrupted, patch to valid version
3. Try: `upx -d target -o unpacked --force`
4. If still fails → `escalate_to: re-dynamic` with note "UPX header tampered, need runtime dump"

### Dynamic dump fallback

```bash
# In gdb, break after UPX stub unpacks to OEP:
gdb -batch -ex "starti" -ex "catch syscall write" -ex "c" -ex "info proc mappings" ./target
# Then dump the .text segment from memory
```

### Why AI models get this wrong

They see "UPX" in strings and assume `upx -d` will work. When it fails, they try random flags (`-f`, `--force`, `--brute`) instead of diagnosing WHY it failed (header corruption). They don't know the specific bytes to patch.

### Rule

**UPX strings present + `upx -t` fails = header tampered.** Check section names and version bytes first. If patching doesn't work within 2 attempts, escalate to re-dynamic for runtime dump.

---

## Case 4: /dev/urandom in Binary

### What you see

```
$ strings target | grep -i random
/dev/urandom

$ IDA decompile main:
fd = open("/dev/urandom", O_RDONLY);
read(fd, iv, 16);
encrypt(input, key, iv, output);
```

### What this means

The binary uses **runtime randomness** as an IV/nonce. This means:
- Each encryption produces different output for the same input
- You CANNOT reproduce the encryption by just running the binary again
- The IV is likely prepended to or stored alongside the ciphertext

### Correct action

1. Check if IV is stored in the .enc file (common: first 16 bytes = IV, rest = ciphertext)
2. `escalate_to: crypto-analyst` with note: "Algorithm uses random IV from /dev/urandom. IV likely stored as first N bytes of .enc file. Key is [found key]. Need to identify cipher and decrypt with extracted IV."

### Why AI models get this wrong

They try to "mock" /dev/urandom (mount --bind /dev/zero, LD_PRELOAD) to make the binary produce deterministic output, then re-encrypt a known plaintext to figure out the algorithm. This is creative but wastes 20+ minutes and often fails due to ASLR/other randomness sources.

### Rule

**`/dev/urandom` + encryption = IV is random but likely stored in output.** Don't try to eliminate randomness. Instead, extract IV from the .enc file and pass both IV + key to crypto-analyst.

---

## Case 5: IDA + gdb Collaboration (Self-Modifying Code)

### What you see

```
IDA decompile main:
void *buf = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, ...);
memcpy(buf, encrypted_code, 0x200);
for (int i = 0; i < 0x200; i++)
    ((char*)buf)[i] ^= key[i % keylen];
((void(*)())buf)();  // jump to decrypted code
```

### Correct workflow (IDA + gdb parallel)

```
1. IDA: decompile → see the XOR decryption loop, identify key and encrypted_code address
2. IDA: get_bytes(instance_id, addr=encrypted_code_addr, size=0x200) → raw encrypted bytes
3. Option A (static): XOR decrypt in Python, patch into IDA:
   python3 -c "..." > /workspace/cache/decrypted_code.bin
   IDA: patch(instance_id, addr=buf_addr, data=<decrypted bytes>)
   IDA: define_code(instance_id, addr=buf_addr)
   IDA: decompile(instance_id, addr=buf_addr)

4. Option B (dynamic): let gdb run past the XOR loop, dump decrypted memory:
   sandbox_exec: gdb -batch -ex "b *<after_xor_loop>" -ex "run" \
     -ex "dump binary memory /workspace/cache/decrypted.bin $rax $rax+0x200" ./target
   Then load dump into IDA for analysis
```

### Why AI models get this wrong

1. They try to decompile the encrypted bytes directly (garbage)
2. They don't realize they can XOR-decrypt statically if they have the key
3. They run the binary without breakpoints and miss the decrypted code entirely
4. They don't feed gdb results back into IDA for further analysis

### Rule

**Self-modifying code = two-phase analysis.** Phase 1: identify the decryption (IDA static). Phase 2: either decrypt statically (if key is known) or dump at runtime (gdb). Phase 3: analyze the decrypted code (IDA again).

---

## Case 6: Anti-Debug with Real Logic in Signal Handler

### What you see

```
IDA decompile:
signal(SIGTRAP, handler);
signal(SIGFPE, handler2);
__asm__("int3");        // triggers SIGTRAP
int x = 1 / 0;         // triggers SIGFPE

void handler(int sig) {
    // REAL flag check logic is HERE
    check_flag(global_input);
}
```

### What this means

The binary uses signal handlers for **actual program logic**, not just anti-debug. Under a debugger, INT3 and division-by-zero are caught by the debugger instead of the signal handler, so the program behaves differently.

### Correct workflow

```
1. IDA: decompile the signal handlers (handler, handler2) — that's where the real logic is
2. For dynamic analysis, configure gdb to pass signals through:
   gdb -ex "handle SIGTRAP nostop pass" -ex "handle SIGFPE nostop pass" ./target
3. Or use strace to observe without intercepting:
   strace -e signal ./target
```

### Why AI models get this wrong

They see `int3` and think "anti-debug, need to NOP it out." But NOPing the INT3 means the signal handler never fires and the real logic never executes. They patch away the trigger instead of analyzing the handler.

### Rule

**Signal setup + intentional trap instruction = logic lives in the handler.** Decompile the handler function, not main. For dynamic work, pass signals through (`handle SIGTRAP nostop pass`).

---

## Case 7: When angr Works vs When It Doesn't

### angr WILL work (use it)

- Input is stdin/argv, < 64 bytes
- Check function is a single path with byte-by-byte comparison
- No floating point, no syscalls beyond read/write
- Clear success/fail addresses visible in IDA (`puts("Correct!")` vs `puts("Wrong")`)
- State space < ~2^20 paths

```python
import angr
p = angr.Project("./target", auto_load_libs=False)
s = p.factory.entry_state()
sm = p.factory.simulation_manager(s)
sm.explore(find=0x401234, avoid=[0x401300])  # addresses from IDA
print(sm.found[0].posix.dumps(0))
```

### angr will NOT work (don't waste time)

- Input > 128 bytes (path explosion)
- Heavy use of libc (printf, malloc, complex string ops)
- Floating point / SIMD operations
- Network I/O or file I/O beyond simple read
- Custom VM with dispatch loop (infinite paths)
- Crypto operations (AES/SHA — symbolic can't invert)

**For these, use**: IDA decompile → manual z3, or IDA + gdb dynamic.

### Why AI models get this wrong

They default to angr for everything because it's "automatic." They let it run for 10+ minutes without checking if it's making progress. They don't set `auto_load_libs=False` (loads full libc symbolically = instant explosion).

### Rule

**Before running angr**: check input size, check for libc complexity, check for crypto. If any red flag → skip angr, go manual z3 or dynamic. If angr doesn't find a solution in 3 minutes, it won't find one in 30 — kill it and switch approach.

---

## Case 8: Statically Linked + Stripped Binary

### What you see

```
$ file target
target: ELF 64-bit LSB executable, x86-64, statically linked, stripped

$ r2 -q -c "afl | wc -l" target
847

$ r2 -q -c "afl | head -5" target
0x00401000    1 43           fcn.00401000
0x0040102b    1 43           fcn.0040102b
...
```

### Problem

847 functions, all named `fcn.XXXXX`. No symbols. r2 can't identify main or libc functions.

### Correct workflow (IDA is critical here)

```
1. IDA: idalib_open → survey_binary
   IDA auto-identifies libc functions via FLIRT signatures (r2 can't do this well)
   → Now you see: main, printf, strcmp, malloc, etc. labeled

2. IDA: list_funcs → find the real application functions (not libc)
   Typically: main calls a few app functions which call libc

3. IDA: decompile(main) → now readable with proper function names

4. If IDA FLIRT doesn't match (custom libc build):
   IDA: xrefs_to("__libc_start_main") → find main
   Or: look for the function that calls the most other functions
```

### Why AI models get this wrong

They try to reverse 847 functions one by one in r2. They can't identify which are libc and which are application code. They waste time on `memcpy` implementations thinking they're custom crypto.

### Rule

**Statically linked + stripped = IDA first, always.** FLIRT signatures identify libc automatically. Without this, you're blind. r2's signature matching (`zg`) is far less reliable.

---

## Case 9: Multi-Stage Decryption (Binary Decrypts Then Executes)

### What you see (IDA decompile)

```c
// Stage 1: decrypt payload
char *payload = malloc(size);
for (int i = 0; i < size; i++)
    payload[i] = encrypted[i] ^ key1[i % key1_len];

// Stage 2: decompress
char *code = zlib_decompress(payload, size, &out_size);

// Stage 3: execute
((void(*)())code)();
```

### Correct workflow

```
1. IDA: get_bytes for encrypted[] array and key1[]
2. Python (in sandbox): XOR decrypt → get compressed payload
3. Python: zlib.decompress(payload) → get stage 2 code
4. Write stage 2 to /workspace/cache/stage2.bin
5. IDA: idalib_open(stage2.bin) → analyze the REAL code
6. The flag logic is in stage 2, not stage 1
```

### Why AI models get this wrong

They analyze stage 1 exhaustively (the loader) instead of extracting and analyzing stage 2 (the payload). They don't realize the interesting code hasn't been written to disk yet.

### Rule

**Decrypt-then-execute = extract the payload, analyze it separately.** The loader is boring. Open the extracted payload as a new binary in IDA.

---

## Case 11: Writing Files in Docker Sandbox (Shell Escaping)

### The problem

You need to write a JSON/Python file inside the sandbox via `sandbox_exec`. But:
- Heredocs (`<< 'EOF'`) behave differently through `docker exec bash -c "..."`
- `$` gets expanded, quotes get eaten, backslashes double
- Python `-c` with nested quotes is a nightmare
- base64 encoding works but is unreadable and error-prone

### What AI models do wrong

They try 15+ variations: heredoc, base64, printf, python3 -c with chr(), echo with \x22 escapes. Each fails for a different quoting reason. 4+ minutes wasted.

### Correct approach

**For JSON files**: use the `write_json` helper (pre-installed in sandbox):

```bash
write_json /workspace/cache/target.triage.json \
  binary=target format=ELF64 arch=x86_64 \
  'key_strings_found=["key1","key2"]' \
  flag_found=null escalate_to=re-static \
  'escalate_reason=Complex obfuscation needs IDA decompile'
```

**For Python scripts**: use base64 one-shot (the ONE pattern that always works):

```bash
echo 'aW1wb3J0IHN5cw...' | base64 -d > /workspace/scripts/solve.py && python3 /workspace/scripts/solve.py
```

**For simple text**: `echo` with single quotes (no variables, no special chars):

```bash
echo 'simple text content' > /workspace/output/result.txt
```

### Rule

**Never fight shell escaping.** Use `write_json` for JSON, base64 one-shot for scripts, single-quoted echo for simple text. If your first attempt fails, don't iterate — switch to a different method immediately.

---

## Case 10: Base64 Table in Binary (Custom Encoding)

### What you see

```
$ strings target
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/

IDA decompile:
char table[] = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/";
encoded = custom_b64_encode(flag, table);
if (strcmp(encoded, "dGVzdA==") == 0) ...
```

### What this means

The binary uses a **custom base64 alphabet** (reversed or shuffled). Standard `base64.b64decode` won't work.

### Correct action

```python
import string
std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
custom = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
encoded = "dGVzdA=="
decoded = base64.b64decode(encoded.translate(str.maketrans(custom, std)))
```

### Why AI models get this wrong

They see base64-looking strings and use standard decode. When it produces garbage, they try other encodings instead of checking if the alphabet is custom.

### Rule

**Base64 table string in binary ≠ standard base64.** Always check if the table matches the standard alphabet. If not, build a translation table and map custom→standard before decoding.
