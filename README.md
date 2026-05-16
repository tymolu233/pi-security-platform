# Pi Security Platform

> **WIP / 半成品** — 核心架构和逆向分析链路基本可用，但多数功能仍在开发中，不建议用于生产环境。

Multi-agent CTF/security analysis platform built on [Pi](https://github.com/badlogic/pi-mono/) (v0.74.0). Delegates security tasks to specialized subagents running in Docker sandboxes.

## Status

| 模块 | 状态 | 说明 |
|------|------|------|
| RE triage → escalation chain | 基本可用 | re-triage → re-static/re-dynamic/re-symbolic 链路已跑通 |
| IDA MCP 集成 | 基本可用 | 需要 IDA Pro 9.0+ 许可证 |
| Docker sandbox | 可用 | 工具链完整，write_json helper 已加 |
| pwn-exploit | 未充分测试 | agent prompt 已写，实际利用链路未验证 |
| web-pentester | 未完善 | 仅有基础 dispatch 扫描，无深度漏洞利用 |
| crypto-analyst | 未充分测试 | 缺少决策案例和算法识别逻辑 |
| recon-specialist | 未完善 | 依赖外部工具（nmap/whois），Windows 兼容性未验证 |
| forensics-analyst | 未完善 | 缺少 skill 子文件和工作流细化 |
| Tier-3 agents (mobile/managed/firmware) | 未实现 | 设计文档在 `docs/future-agents.md` |
| 跨 agent 协作 | 部分可用 | redirect_to 协议已定义，实际多跳场景未充分测试 |
| 时间预算强制执行 | 仅靠 prompt | 无运行时强制机制，agent 可能超时 |

## Known Issues

- subagent 写文件到 sandbox 时偶尔遇到 shell 转义问题（已通过 `write` 工具 + host 直写缓解，但未完全消除）
- `MAX N calls` 限制仅靠 prompt 约束，无代码级强制
- IDA `idalib_open` 在 Python 版本不匹配时静默失败
- Windows 下 `dockerExec` 使用 base64 管道方案，长命令可能超出命令行长度限制
- 非 RE 类 agent（web/recon/forensics）的 skill 内容较薄，缺少 agent-cases 类决策案例

## Architecture

```
Pi Agent (orchestrator)
  ├── security-platform extension  → sandbox tools, dispatch, report
  ├── pi-subagents                 → subagent delegation
  ├── pi-mcp-adapter               → IDA Pro MCP bridge
  └── Subagents (9)
       ├── re-triage         → fast triage + escalation (2-5 min)
       ├── re-static         → IDA decompile, deobfuscate, custom VM
       ├── re-dynamic        → IDA + gdb/frida/strace parallel
       ├── re-symbolic       → IDA decompile → z3/angr
       ├── pwn-exploit       → pwntools, ROP, heap
       ├── crypto-analyst    → cipher/hash analysis
       ├── web-pentester     → web vuln scanning
       ├── recon-specialist  → OSINT & recon
       └── forensics-analyst → disk/memory/pcap
```

### RE escalation chain

```
User request → Main agent → re-triage (2-5 min)
                                ├── flag found → done
                                └── escalate_to: re-static / re-dynamic / re-symbolic / pwn-exploit / crypto-analyst
                                         ├── IDA decompile (mandatory first step)
                                         ├── sandbox analysis
                                         └── result or redirect_to: <peer>
```

## Skills (5 packages, distributed)

| Package | Files | Coverage |
|---------|-------|----------|
| ctf-reverse | 20 | RE 全栈：工具/模式/语言/平台/案例 |
| ctf-pwn | 19 | 漏洞利用：栈/堆/格式化/内核/沙箱逃逸 |
| radare2 | 3 | r2 命令速查 + recon 脚本 |
| rev-struct | 1 | 结构体恢复 |
| rev-symbol | 1 | 符号恢复 |

## Docker Sandbox

Pre-built Ubuntu 22.04 image with:

- **RE**: radare2, pwndbg, gdb, strace, ltrace, angr, frida, capstone, qiling
- **Pwn**: pwntools, ROPgadget, ropper, one_gadget
- **Crypto**: pycryptodome, z3-solver, gmpy2
- **Forensics**: binwalk, foremost, tshark
- **QEMU**: system-x86, user-static
- **Helpers**: write_json (避免 shell 转义)

```bash
docker build -t pi-security-sandbox -f docker/Dockerfile.sandbox docker/
```

## Quick Start

```bash
# 1. Install Pi packages
pi install npm:pi-subagents
pi install npm:pi-mcp-adapter
pi install npm:pi-web-access

# 2. Build sandbox
docker build -t pi-security-sandbox -f docker/Dockerfile.sandbox docker/

# 3. (Optional) Install IDA MCP
pip install git+https://github.com/MeroZemory/ida-multi-mcp.git

# 4. Start Pi
pi
```

Then:

```
逆向分析 /path/to/binary
```

See [INSTALL.md](INSTALL.md) for detailed setup.

## Contributing

This is a personal research project. PRs welcome for:
- Non-RE agent skill content (web/crypto/forensics cases)
- Agent decision cases (`agent-cases.md` format)
- Docker toolchain additions
- Bug fixes in the extension code

## License

MIT
