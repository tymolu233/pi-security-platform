// .pi/extensions/security-platform/tools/dispatch.ts
import { Type } from "typebox";
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { detectTargetType, extractHost, recommendAgent, quickFileType } from "../utils/detect.js";
import { getSharedWorkspace, logCommand } from "../utils/workspace.js";

function tryExec(cmd: string, timeoutMs: number): { ok: boolean; out: string } {
  try {
    const out = execSync(cmd, { timeout: timeoutMs, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] } as any);
    return { ok: true, out };
  } catch (err: any) {
    return { ok: false, out: err.message || String(err) };
  }
}

export function createDispatchTool() {
  return {
    name: "security_dispatch",
    label: "Security Dispatch",
    description: "自动识别目标类型（URL/域名/IP/文件），执行对应安全分析。",
    parameters: Type.Object({
      target: Type.String({ description: "目标：URL、域名、IP 或文件路径" }),
      depth: Type.Optional(Type.String({ description: "扫描深度: quick/normal/deep（默认 normal）" })),
    }),
    async execute(toolCallId: string, params: any) {
      const { target, depth = "normal" } = params;
      const targetType = detectTargetType(target);
      const recommendedAgent = recommendAgent(target, targetType);
      const results: string[] = [];
      const findings: any[] = [];

      // Ensure shared workspace exists early — even pure recon should leave a footprint
      const workspace = getSharedWorkspace();

      results.push(`Target: ${target}`);
      results.push(`Type: ${targetType}`);
      results.push(`Depth: ${depth}`);
      results.push(`Workspace: ${workspace}`);
      results.push(`Recommended agent: ${recommendedAgent}`);
      results.push(`Next: subagent({ agent: "${recommendedAgent}", task: "..." })`);
      results.push("");

      if (targetType === "file") {
        results.push("=== Binary Analysis ===");
        if (existsSync(target)) {
          const fileInfo = quickFileType(target);
          results.push(fileInfo);
          results.push("\nRecommended: Load `ctf-reverse` skill for analysis guidance");
          results.push(`Use sandbox_init path="${target}"`);
          findings.push({ type: "binary", content: fileInfo });
        } else {
          results.push(`File not found: ${target}`);
        }
      } else {
        results.push("Recommended: Load `ctf-web` + `ctf-osint` skills for attack guidance");
        const host = extractHost(target);

        // Recon
        results.push("\n=== Recon ===");
        const whois = tryExec(`whois ${host}`, 15000);
        if (whois.ok) results.push(`WHOIS:\n${whois.out.slice(0, 800)}...`);
        else results.push(`WHOIS skipped: ${whois.out.slice(0, 120)}`);

        const dns = tryExec(`nslookup ${host}`, 10000);
        if (dns.ok) results.push(`\nDNS:\n${dns.out}`);
        else results.push(`DNS skipped: ${dns.out.slice(0, 120)}`);

        // Port Scan
        results.push("\n=== Port Scan ===");
        const ports = depth === "quick" ? "--top-ports 10" : depth === "deep" ? "-p-" : "--top-ports 100";
        const nmapTimeout = depth === "deep" ? 300000 : 60000;
        const nmap = tryExec(`nmap -sV ${ports} ${host}`, nmapTimeout);
        if (nmap.ok) { results.push(nmap.out); findings.push({ type: "ports", content: nmap.out }); }
        else results.push(`Scan skipped: ${nmap.out.slice(0, 120)}`);

        // HTTP Probe
        results.push("\n=== HTTP Probe ===");
        const url = target.startsWith("http") ? target : `http://${target}`;
        const headers = tryExec(`curl -sI -m 10 "${url}"`, 15000);
        if (headers.ok) { results.push(headers.out); findings.push({ type: "http", content: headers.out }); }
        else results.push(`Probe skipped: ${headers.out.slice(0, 120)}`);

        // Path Discovery
        if (depth !== "quick") {
          results.push("\n=== Path Discovery ===");
          const paths = ["/admin", "/login", "/.git", "/robots.txt", "/sitemap.xml", "/api", "/swagger"];
          for (const p of paths) {
            const probe = tryExec(`curl -s -o /dev/null -w "%{http_code}" -m 5 "${url}${p}"`, 10000);
            if (probe.ok) {
              const status = probe.out.trim();
              if (status && status !== "000" && status !== "404") {
                results.push(`  ${p} → ${status}`);
                findings.push({ type: "path", content: `${url}${p} → ${status}` });
              }
            }
          }
        }
      }

      // Summary
      results.push("\n=== Summary ===");
      results.push(`Findings: ${findings.length}`);
      if (findings.length > 0) {
        for (const f of findings) {
          results.push(`- [${f.type}] ${f.content.slice(0, 100)}`);
        }
      }

      logCommand("dispatch", `security_dispatch(${target}, ${depth})`);

      return {
        content: [{ type: "text", text: results.join("\n") }],
        details: { target, targetType, depth, findings, recommended_agent: recommendedAgent, workspace },
      };
    },
  };
}
