---
name: ctf-reverse
description: CTF 逆向工程技术。当任务是理解编译/混淆/打包/虚拟化目标的工作原理时使用，包括二进制、APK、WASM、固件、自定义 VM、字节码、游戏客户端、恶意加载器和反调试逻辑。漏洞已明确需要利用时用 ctf-pwn；纯 web/取证/密码学问题不用本 skill 除非逆向实现是真正的阻塞点。
---

# CTF Reverse Engineering

## Gotchas

- 发现 key/password 字符串后不要自己尝试解密——记录并 escalate 给 crypto-analyst
- 不要全量加载所有子文件——按懒加载表按需读取
- UPX 字符串存在但 `upx -d` 失败 = header 被篡改，不要反复尝试不同 flag
- `/dev/urandom` 在二进制中 = 运行时随机 IV，不要试图消除随机性
- angr 跑 3 分钟没结果就不会有结果——切换到手动 z3
- 信号处理函数（SIGTRAP/SIGFPE handler）里可能有真实逻辑，不要 NOP 掉触发指令
- 静态链接+stripped 二进制必须用 IDA（FLIRT 签名），r2 识别不了 libc 函数

## Docker Sandbox 规则

**二进制分析必须在 Docker 中执行**，结果返回后在本机解读。

| 环境 | 命令 |
|------|------|
| Docker | `file`, `strings`, `readelf`, `objdump`, `xxd`, `r2`, `gdb`, `strace`, `ltrace`, `frida`, `angr`, `qiling`, `capstone`, `unicorn`, `upx`, `apktool`, `uncompyle6` |
| 本机 | `python3`（z3/sympy 求解）、IDA via MCP |

```
sandbox_init(path="binary")
sandbox_exec(cmd="r2 -q -c 'aaa; pdf @ entry0' /workspace/targets/sample")
# 求解部分在本机或 IDA
mcp__ida-multi-mcp__decompile({instance_id, function_name: "main"})
```

## Problem-Solving Workflow

1. **strings** — 很多简单题有明文 flag
2. **ltrace/strace** — 动态分析常直接暴露 flag
3. **IDA decompile** — Hex-Rays 输出比 r2ghidra 质量高得多
4. **Frida hooking** — hook strcmp/memcmp 捕获期望值
5. **angr/z3** — 符号执行解决有界 flag-checker
6. **Qiling** — 模拟外架构或绕过重度反调试
7. **Map control flow** — 修改执行前先理解结构
8. **Automate** — r2pipe/Frida/angr/Python 脚本化重复操作

## When to Pivot

- 漏洞已明确，需要利用 → `ctf-pwn`
- 恢复删除文件/PCAP/磁盘取证 → `ctf-forensics`
- Web 应用，只逆向客户端小脚本 → `ctf-web`
- ML 模型攻击/对抗输入 → `ctf-ai-ml`
- 核心逻辑是密码学算法/数学 → `ctf-crypto`
- 真实恶意软件（C2/打包/规避） → `ctf-malware`
- 玩具 VM/编码谜题/pyjail → `ctf-misc`

## Additional Resources（按需加载）

| 何时读 | 文件 |
|---|---|
| 不确定该怎么做 | [agent-cases.md](agent-cases.md) — 10+ 决策案例 |
| 需要具体工具用法 | [tools.md](tools.md) — 静态工具（r2/IDA/Ghidra/Binary Ninja/dogbolt） |
| 动态分析详情 | [tools-dynamic.md](tools-dynamic.md) — Frida/angr/lldb/x64dbg |
| 模拟/侧信道 | [tools-emulation.md](tools-emulation.md) — Qiling/Triton/Pin |
| 高级工具 | [tools-advanced.md](tools-advanced.md) — VMProtect/BinDiff/deobfuscation |
| 高级 GDB/patching | [tools-advanced-2.md](tools-advanced-2.md) — GDB scripting/LIEF/rr |
| 反分析对抗 | [anti-analysis.md](anti-analysis.md) — Linux/Windows anti-debug/anti-VM |
| CTF 反分析技巧 | [anti-analysis-ctf.md](anti-analysis-ctf.md) — 信号/trace/parent-patch |
| 基础模式 | [patterns.md](patterns.md) — 自定义 VM/XOR/自修改代码/S-box |
| 运行时模式 | [patterns-runtime.md](patterns-runtime.md) — 运行时 patch/oracle |
| CTF 竞赛模式 1-3 | [patterns-ctf.md](patterns-ctf.md), [-2](patterns-ctf-2.md), [-3](patterns-ctf-3.md) |
| 语言特定 | [languages.md](languages.md) — Python/esolang/UEFI/OPAL |
| 平台/框架 | [languages-platforms.md](languages-platforms.md) — Roblox/Godot/Electron/Android |
| 编译型语言 | [languages-compiled.md](languages-compiled.md) — Go/Rust/Swift/Kotlin/Haskell/C++ |
| 平台 RE | [platforms.md](platforms.md) — macOS/iOS/embedded/kernel/game engine |
| 硬件/架构 | [platforms-hardware.md](platforms-hardware.md) — RISC-V/ARM64/LCD GPIO |
| 快速参考 | [field-notes.md](field-notes.md) — 二进制类型/反调试/专项模式/CTF 笔记 |
