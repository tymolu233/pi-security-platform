# Future Agents Roadmap

Status: **planned, not implemented.** This doc captures the design for Tier-3 specialist RE agents. Build them when current Tier-2 agents (`re-static` / `re-dynamic` / `re-symbolic`) repeatedly underperform on a specific binary class.

## Trigger to implement

Promote a Tier-3 agent from this doc to `.pi/agents/` when:

- You see ≥5 tasks of that class in a month
- The success rate for that class through Tier-2 is below the platform average
- The failure modes share a root cause that Tier-2's generic toolchain doesn't address

Until then, Tier-2 (`re-static` / `re-dynamic`) handles these classes generically.

---

## re-mobile (Android/iOS RE)

**Domain**: APK, IPA, DEX, ART/OAT, native `.so`/`.dylib`, iOS Mach-O, Frida-on-mobile hooks.

**Why split from re-static**:
- Toolchain is entirely different (jadx, apktool, dex2jar, frida-server-android, class-dump, ipatool)
- DEX/SMALI bytecode lifting is its own discipline
- Native bridge analysis (JNI RegisterNatives obfuscation) needs cross-language tracing
- iOS code signing, dyld, ObjC runtime introspection require iOS-specific knowledge

**Suggested config**:
```yaml
name: re-mobile
description: Mobile RE - Android (APK/DEX) and iOS (IPA/Mach-O)
tools: sandbox_init, sandbox_exec, sandbox_install
skills: ctf-reverse
```

**Skill sub-files to load on demand**:
- `ctf-reverse/languages-platforms.md` — JNI RegisterNatives obfuscation, DEX runtime patching, ASAR
- `ctf-reverse/platforms.md` — macOS/iOS Mach-O, Objective-C runtime, dyld, jailbreak bypass
- `ctf-reverse/languages.md` — Python bytecode (also applies to managed)
- `ctf-reverse/languages-compiled.md` — Kotlin/JVM coroutine state machines

**Tools to add to Dockerfile.sandbox**:
- jadx (`apt install jadx` or release tarball)
- apktool
- dex2jar
- frida-server-android binaries (multiple arches)
- objection
- class-dump-z (iOS)
- ldid (iOS code signing)
- bytecode-viewer

**Example tasks**:
- "Analyze /workspace/app.apk, find the flag in MainActivity"
- "Hook native lib in /workspace/native.so via frida-android"
- "Extract IPA assets and find embedded keys"

**Boundary**:
- Real malware sample → `redirect_to: forensics-analyst`
- iOS exploit dev → `redirect_to: pwn-exploit` (after RE)
- Mobile webview JS reversing → use `js-reverse-automation` skill (already exists in main agent)

---

## re-managed (Managed-code RE)

**Domain**: .NET (PE with CLR), JVM (.jar, .class), Python bytecode (.pyc, frozen), Lua bytecode, WASM, Electron ASAR.

**Why split from re-static**:
- Decompilers produce near-source output — different workflow than native disasm
- Tooling is per-runtime: dnSpy/ILSpy/dotPeek for .NET, CFR/Procyon/Krakatau for JVM, uncompyle6/pycdc for Python
- Obfuscators are runtime-specific (ConfuserEx, ProGuard, PyArmor, javascript-obfuscator)
- WASM tooling (wabt, wasm-decompile, ghidra-wasm) is separate

**Suggested config**:
```yaml
name: re-managed
description: Managed-code RE - .NET, JVM, Python bytecode, WASM, Lua
tools: sandbox_init, sandbox_exec, sandbox_install
skills: ctf-reverse
```

**Skill sub-files**:
- `ctf-reverse/languages.md` — Python bytecode/opcode remapping, PyArmor, esolangs, IL2CPP, HarmonyOS HAP/ABC
- `ctf-reverse/languages-compiled.md` — JVM/Kotlin coroutines
- `ctf-reverse/languages-platforms.md` — Electron ASAR, Node.js npm runtime

**Tools to add to Dockerfile.sandbox**:
- mono + ilspycmd (.NET CLI decompile)
- cfr-decompiler.jar, procyon-decompiler.jar (JVM)
- uncompyle6, decompyle3, pycdc (Python; pycdc must be built from source)
- wabt (wasm2wat, wasm-decompile)
- de4dot (.NET deobfuscation)
- ConfuserEx-Unpacker

**Example tasks**:
- "Decompile /workspace/app.exe (.NET), find the license check"
- "Recover Python source from /workspace/frozen.bin"
- "Decompile /workspace/module.wasm and find the validator"

**Boundary**:
- Native side of a managed app (JNI, P/Invoke target) → `redirect_to: re-static`
- Obfuscated JS → use `js-reverse-automation` skill in main agent

---

## re-firmware (Embedded/Firmware RE)

**Domain**: Router/IoT firmware images, MCU dumps, RTOS, ARM/MIPS/RISC-V, hardware-RE (UART/JTAG dumps), kernel drivers (.ko/.sys), eBPF programs.

**Why split from re-static**:
- Filesystem extraction (binwalk multi-layer, squashfs, UBI, CramFS, JFFS2) is a distinct workflow
- Cross-arch emulation (qemu-system, qemu-user-static with custom rootfs) needs setup
- Bootloader / U-Boot / TrustZone analysis is its own domain
- Embedded toolchains: vendor SDKs, custom RTOS symbols, real-time constraints

**Suggested config**:
```yaml
name: re-firmware
description: Firmware/embedded RE - router/IoT/MCU, cross-arch emulation, hardware dumps
tools: sandbox_init, sandbox_exec, sandbox_install
skills: ctf-reverse
```

**Skill sub-files**:
- `ctf-reverse/platforms.md` — embedded/IoT firmware (binwalk, UART/JTAG/SPI, ARM/MIPS, RTOS), kernel drivers
- `ctf-reverse/platforms-hardware.md` — HD44780 LCD GPIO reconstruction, RISC-V advanced, ARM64 reversing+exploitation, qemu-aarch64-static

**Tools to add to Dockerfile.sandbox**:
- binwalk (already present, ensure with all extractors)
- firmware-mod-kit (or binwalk --extract --matryoshka)
- squashfs-tools, ubi-utils, jefferson, cramfsswap
- qemu-system-arm, qemu-system-mips, qemu-system-riscv64
- qemu-user-static (multiarch)
- firmware analysis toolkits: FACT, EMBA (heavy, optional)
- ghidra (with FunctionID for unknown vendor symbols)
- ImHex (binary template editor)

**Example tasks**:
- "Extract filesystem from /workspace/router.bin and find hardcoded credentials"
- "Emulate /workspace/firmware.img under qemu-system-arm with vendor NVRAM mock"
- "Analyze SPI flash dump /workspace/dump.bin, identify boot stages"

**Boundary**:
- Pure RTOS binary without firmware wrapper → `redirect_to: re-static`
- Exploiting firmware vuln (after RE done) → `redirect_to: pwn-exploit`
- Network protocol traffic from firmware → `redirect_to: forensics-analyst`

---

## Cross-cutting work (do when implementing Tier 3)

### Update `recommendAgent` in `detect.ts`

Refine file-type → agent mapping:

```ts
const MOBILE_EXTENSIONS = [".apk", ".dex", ".ipa", ".aab"];
const MANAGED_EXTENSIONS = [".pyc", ".class", ".jar", ".wasm", ".asar"];
const FIRMWARE_EXTENSIONS = [".img", ".bin"]; // ambiguous with raw disk — needs header check
const DOT_NET_HINT = (target: string) => { /* peek PE for CLR header */ };

export function recommendAgent(target: string, targetType: TargetType): string {
  if (targetType === "file") {
    const ext = extname(target).toLowerCase();
    if (FORENSICS_EXTENSIONS.includes(ext)) return "forensics-analyst";
    if (CRYPTO_EXTENSIONS.includes(ext)) return "crypto-analyst";
    if (MOBILE_EXTENSIONS.includes(ext)) return "re-mobile";
    if (MANAGED_EXTENSIONS.includes(ext) || DOT_NET_HINT(target)) return "re-managed";
    if (FIRMWARE_EXTENSIONS.includes(ext) /* and binwalk signature check */) return "re-firmware";
    return "re-triage";
  }
  // ... rest unchanged
}
```

### Update `index.ts` dispatch table

Add Tier-3 rows to the markdown table in `before_agent_start`.

### Update `re-triage` escalation rules

Add Tier-3 escalation targets in the triage `.md`:

```
| APK/DEX/IPA detected | re-mobile |
| .NET CLR / JVM .class / Python .pyc | re-managed |
| binwalk shows filesystem inside | re-firmware |
```

### Update Dockerfile.sandbox

Add Tier-3 tool installs in a separate stage / layer to keep image rebuild times reasonable. Tag the image with `pi-security-sandbox:tier3` if you want to keep a slim default.

---

## Why these are Tier 3 (not Tier 2)

| Reason | Detail |
|---|---|
| Optional toolchain weight | Each adds 1-3 GB to sandbox image |
| Lower frequency | Most CTF RE chals are native Linux ELF (Tier-2 handles) |
| Diminishing return on splits | `re-static` with `languages-platforms.md` loaded already covers many mobile cases |
| Maintenance cost | Mobile tooling especially churns quickly (Frida/Android version pinning) |

Build them when you have evidence of the need, not preemptively.
