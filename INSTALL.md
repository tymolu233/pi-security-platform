# Installation

## Prerequisites

- [Pi](https://github.com/badlogic/pi-mono/) v0.74.0+
- Docker Desktop
- IDA Pro 9.0+ (optional, for `mcp:ida-multi-mcp`)
- Python 3.11+ (matching IDA's Python version if using IDA)

## Setup

### 1. Copy to your project

```bash
# Clone this repo
git clone https://github.com/<your-org>/pi-security-platform.git

# Copy .pi/ into your project root
cp -r pi-security-platform/.pi /path/to/your/project/
cp -r pi-security-platform/docker /path/to/your/project/
cp -r pi-security-platform/docs /path/to/your/project/
```

Or use it directly as your project root.

### 2. Install Pi packages

```bash
cd /path/to/your/project
pi install npm:pi-subagents
pi install npm:pi-mcp-adapter
pi install npm:pi-web-access
```

### 3. Build Docker sandbox

```bash
docker build -t pi-security-sandbox -f docker/Dockerfile.sandbox docker/
```

### 4. Configure IDA MCP (optional)

If you have IDA Pro installed:

```bash
pip install git+https://github.com/MeroZemory/ida-multi-mcp.git
```

Edit `.pi/mcp.json` to point to your Python path:

```json
{
  "mcpServers": {
    "ida-multi-mcp": {
      "command": "/path/to/python3.11",
      "args": ["-m", "ida_multi_mcp"],
      "lifecycle": "lazy",
      "idleTimeout": 30,
      "directTools": true
    }
  }
}
```

### 5. Restart Pi

```bash
# Pi will load the extension, agents, skills, and MCP config
pi
```

## Verification

After starting Pi, you should see:

```
[Extensions]
  security-platform, pi-mcp-adapter, pi-subagents, pi-web-access

[Skills]
  ctf-reverse, ctf-pwn, radare2, rev-struct, rev-symbol, ...
```

Test with:

```
分析 /path/to/some/binary
```

Pi should dispatch to `re-triage` automatically.

## File Structure

```
.pi/
├── settings.json              — Pi config (packages, agents, extensions)
├── mcp.json                   — MCP server config (ida-multi-mcp)
├── agents/                    — 9 subagent definitions
│   ├── re-triage.md           — Fast triage (2-5 min)
│   ├── re-static.md           — Heavy static RE (IDA primary)
│   ├── re-dynamic.md          — Runtime RE (IDA + gdb)
│   ├── re-symbolic.md         — Symbolic execution (angr/z3)
│   ├── pwn-exploit.md         — Exploit development
│   ├── crypto-analyst.md      — Cryptography
│   ├── web-pentester.md       — Web security
│   ├── recon-specialist.md    — OSINT/recon
│   └── forensics-analyst.md   — Digital forensics
├── extensions/security-platform/  — Core extension
│   ├── index.ts               — System prompt injection + tool registration
│   ├── types.ts               — Type definitions
│   ├── tools/                 — dispatch, report, sandbox tools
│   └── utils/                 — detect, docker, workspace helpers
└── skills/                    — 5 skill packages
    ├── ctf-reverse/           — 20 reference files (primary RE skill)
    ├── ctf-pwn/               — 19 reference files (exploitation)
    ├── radare2/               — r2 command reference
    ├── rev-struct/            — Structure recovery
    └── rev-symbol/            — Symbol recovery
docker/
├── Dockerfile.sandbox         — Ubuntu 22.04 + full RE/pwn toolchain
├── recon.sh                   — r2 recon script
└── write_json.py              — JSON write helper (avoids shell escaping)
docs/
├── ida-mcp-usage.md           — IDA MCP usage guide for agents
└── future-agents.md           — Tier-3 agent roadmap (mobile/managed/firmware)
```
