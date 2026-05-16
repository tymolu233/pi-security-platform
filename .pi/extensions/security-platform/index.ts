// .pi/extensions/security-platform/index.ts
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { createDispatchTool } from "./tools/dispatch.js";
import { createReportTool } from "./tools/report.js";
import {
  createSandboxInitTool,
  createSandboxExecTool,
  createSandboxInstallTool,
  createSandboxListTool,
  createSandboxReconnectTool,
  createSandboxCleanupTool,
} from "./tools/sandbox.js";

export default function (pi: ExtensionAPI) {
  // System prompt — guide delegation without blocking tools
  pi.on("before_agent_start", async (event, ctx) => {
    return {
      systemPrompt:
        event.systemPrompt +
        "\n\n## Security Platform\n\n" +
        "**You are an orchestrator.** For any security task (binary analysis, web pentest, crypto, forensics, OSINT), delegate to a specialized subagent via `subagent({...})`. **Do NOT call `sandbox_init` / `sandbox_exec` / `sandbox_install` / `sandbox_cleanup` yourself** — those are subagent tools. You only call `security_dispatch` (for triage/recon) and `subagent` (for delegation) and `security_report` (at the end).\n\n" +
        "**File write rule**: ALL files created by subagents MUST go in the workspace directory (`/workspace/` inside sandbox). Specifically: scripts → `/workspace/scripts/`, analysis cache → `/workspace/cache/`, final output → `/workspace/output/`. Writing to `/tmp/` or any path outside `/workspace/` is PROHIBITED.\n\n" +
        "| Task | Agent |\n" +
        "|------|-------|\n" +
        "| binary/RE/file analysis | re-triage (auto-escalates to re-static / re-dynamic / re-symbolic) |\n" +
        "| exploit/pwn development | pwn-exploit |\n" +
        "| web/URL/IP scanning | web-pentester |\n" +
        "| crypto/encryption/hash | crypto-analyst |\n" +
        "| recon/OSINT | recon-specialist |\n" +
        "| forensics/malware/pcap | forensics-analyst |\n\n" +
        "### Dispatch protocol\n\n" +
        "1. If target type is unclear, call `security_dispatch` first — it returns `recommended_agent` in `details` plus initial scan output.\n" +
        "2. Call `subagent({ agent: <recommended_agent>, task: <task with context from step 1> })`.\n" +
        "3. If a subagent returns `redirect_to: <other-agent>` in its report, re-dispatch to that agent with the original task plus any partial findings.\n\n" +
        "### RE escalation chain\n\n" +
        "Binary/RE tasks ALWAYS start with `re-triage` (fast quick-wins, 2-5 min). It will either return a flag or an `escalate_to` hint. Read the hint and dispatch:\n" +
        "- `escalate_to: re-static` — heavy decompile, deobfuscation, custom VM\n" +
        "- `escalate_to: re-dynamic` — debug/trace/hook/emulate (anti-static, packed, runtime crypto)\n" +
        "- `escalate_to: re-symbolic` — angr/z3 for complex flag-checker logic\n" +
        "- `escalate_to: pwn-exploit` — vulnerable binary needing exploitation\n" +
        "- `escalate_to: crypto-analyst` — found encryption key/algorithm, need crypto expertise to decrypt\n\n" +
        "Pass triage's findings forward in `task` so the next agent doesn't redo work. Subagents share `/workspace/cache/` inside the sandbox for intermediate artifacts.\n\n" +
        "### IDA Pro MCP (RE subagents only)\n\n" +
        "`mcp:ida-multi-mcp` is wired only into RE subagents (`re-triage`, `re-static`, `re-dynamic`, `re-symbolic`, `pwn-exploit`). You (main agent) and non-RE subagents do NOT have it. IDA runs **locally on the host, not in the sandbox** — it is the single binary-related toolchain that bypasses sandbox execution. If a user asks for IDA-style analysis, dispatch to an RE subagent; the subagent will call `mcp__ida-multi-mcp__idalib_open` itself. Detailed usage lives in `docs/ida-mcp-usage.md`.\n\n" +
        "Example:\n" +
        'subagent({ agent: "re-triage", task: "Analyze /path/to/binary, find flag" })\n\n' +
        "Subagents have isolated tool whitelists and cannot dispatch each other — cross-domain routing always comes back through the main agent.\n",
    };
  });

  // Register tools — available to subagents via whitelist; main agent is told NOT to use sandbox tools directly
  pi.registerTool(createDispatchTool());
  pi.registerTool(createReportTool());
  pi.registerTool(createSandboxInitTool());
  pi.registerTool(createSandboxExecTool());
  pi.registerTool(createSandboxInstallTool());
  pi.registerTool(createSandboxListTool());
  pi.registerTool(createSandboxReconnectTool());
  pi.registerTool(createSandboxCleanupTool());

  // Commands
  pi.registerCommand("scan", {
    description: "安全扫描",
    handler: async (args, ctx) => {
      if (!args) { ctx.ui.notify("用法: /scan <target>", "warn"); return; }
      await ctx.sendUserMessage(`security_dispatch target="${args}"`);
    },
  });

  pi.registerCommand("sandbox", {
    description: "沙箱管理",
    handler: async (args, ctx) => {
      const [action, ...rest] = (args || "").split(" ");
      if (action === "init") await ctx.sendUserMessage(`sandbox_init path="${rest[0] || "."}"`);
      else if (action === "list") await ctx.sendUserMessage("sandbox_list");
      else ctx.ui.notify("用法: /sandbox <init|list> [args]", "warn");
    },
  });
}
