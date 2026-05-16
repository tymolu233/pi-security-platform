// .pi/extensions/security-platform/tools/report.ts
import { Type } from "typebox";
import { basename } from "node:path";
import { getSharedWorkspace, loadProgress, loadContainers } from "../utils/workspace.js";

export function createReportTool() {
  return {
    name: "security_report",
    label: "Security Report",
    description: "生成综合安全报告",
    parameters: Type.Object({}),
    async execute() {
      const containers = loadContainers();
      const active = Object.values(containers).filter(c => c.status === "running");
      const workspace = getSharedWorkspace();
      const progress = loadProgress();

      let report = "# Security Report\n\n";
      report += `Generated: ${new Date().toISOString()}\n\n`;

      if (active.length > 0) {
        report += "## Active Analysis\n\n";
        for (const c of active) {
          report += `### ${basename(c.file)}\n`;
          report += `- Container: ${c.id.slice(0, 12)}\n\n`;
        }
      }

      if (progress.commands.length > 0) {
        report += "## Commands Executed\n\n";
        for (const cmd of progress.commands.slice(-10)) {
          report += `- [${cmd.container || "?"}] ${cmd.cmd}\n`;
        }
        report += "\n";
      }

      if (progress.findings.length > 0) {
        report += "## Findings\n\n";
        const byType: Record<string, string[]> = {};
        for (const f of progress.findings) {
          if (!byType[f.type]) byType[f.type] = [];
          byType[f.type].push(f.content);
        }
        for (const [type, items] of Object.entries(byType)) {
          report += `### ${type.toUpperCase()}\n`;
          for (const item of items.slice(0, 10)) {
            report += `- ${item.slice(0, 150)}\n`;
          }
          if (items.length > 10) report += `- ... and ${items.length - 10} more\n`;
          report += "\n";
        }
      }

      report += "## Workspace\n\n";
      report += `- Path: ${workspace}\n`;
      report += `- Targets: /workspace/targets/\n`;
      report += `- Output: /workspace/output/\n`;
      report += `- Logs: /workspace/logs/\n`;

      return {
        content: [{ type: "text", text: report }],
        details: { activeContainers: active.length, findings: progress.findings.length },
      };
    },
  };
}
