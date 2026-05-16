// .pi/extensions/security-platform/tools/sandbox.ts
import { Type } from "typebox";
import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { basename, join } from "node:path";
import { dockerExec, dockerRm, isContainerRunning, getShell, winPath } from "../utils/docker.js";
import { getSharedWorkspace, addToWorkspace, logCommand, saveProgress, loadProgress, loadContainers, saveContainers, getContainerForFile } from "../utils/workspace.js";
import type { ContainerInfo } from "../types.js";

export function createSandboxInitTool() {
  return {
    name: "sandbox_init",
    label: "Init Sandbox",
    description: "创建 Docker 工作区，启动容器",
    parameters: Type.Object({
      path: Type.String({ description: "二进制文件路径" }),
      files: Type.Optional(Type.Array(Type.String(), { description: "额外文件" })),
    }),
    async execute(toolCallId: string, params: any, ctx: any) {
      const { path, files } = params;
      const cwd = ctx?.cwd || process.cwd();
      const absPath = path.startsWith("/") || path.match(/^[A-Z]:\\/i) ? path : join(cwd, path);

      if (!existsSync(absPath)) {
        return { content: [{ type: "text", text: `File not found: ${absPath}` }], details: {}, isError: true };
      }

      const existingId = getContainerForFile(absPath);
      if (existingId) {
        const containers = loadContainers();
        return {
          content: [{ type: "text", text: `Reusing container ${existingId.slice(0, 12)}\nWorkspace: ${containers[existingId].workspace}\nUse sandbox_exec to continue.` }],
          details: { containerId: existingId, reused: true },
        };
      }

      const workspacePath = addToWorkspace(absPath, files, cwd);
      const dockerWorkspace = winPath(workspacePath);
      const shell = getShell();

      try {
        const containerId = execSync(
          `docker run -d --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "${dockerWorkspace}:/workspace" pi-security-sandbox sleep 86400`,
          { encoding: "utf-8", shell } as any
        ).trim();

        try {
          execSync(`docker exec ${containerId} bash -c "cp /opt/scripts/recon.sh /workspace/scripts/ 2>/dev/null || true"`, { encoding: "utf-8", shell } as any);
        } catch {}

        const containers = loadContainers();
        containers[containerId] = {
          id: containerId, file: absPath, workspace: workspacePath,
          createdAt: new Date().toISOString(), status: "running", lastActivity: new Date().toISOString(),
        };
        saveContainers(containers);

        const tools = dockerExec(containerId, "which r2 gdb strace ltrace file readelf strings objdump xxd python3 2>/dev/null | xargs -I{} basename {}").trim();
        const fileName = basename(absPath);
        const fileInfo = dockerExec(containerId, `file /workspace/targets/${fileName}`).trim();

        return {
          content: [{ type: "text", text: `Sandbox ready!\nContainer: ${containerId.slice(0, 12)}\nFile: ${fileInfo}\nTools: ${tools}\n\nShared workspace: ${workspacePath}\n- /workspace/targets/ (input)\n- /workspace/output/ (results)\n- /workspace/scripts/ (tools)\n- /workspace/logs/ (history)\n\nUse sandbox_exec(container="${containerId.slice(0, 12)}", command="...")` }],
          details: { containerId, workspace: workspacePath, fileInfo, tools },
        };
      } catch (err: any) {
        return { content: [{ type: "text", text: `Failed: ${err.message}` }], details: {}, isError: true };
      }
    },
  };
}

export function createSandboxExecTool() {
  return {
    name: "sandbox_exec",
    label: "Exec in Sandbox",
    description: "在 Docker 沙箱执行命令",
    parameters: Type.Object({
      container: Type.String({ description: "容器 ID" }),
      command: Type.String({ description: "命令" }),
      timeout: Type.Optional(Type.Number({ description: "超时秒数" })),
    }),
    async execute(toolCallId: string, params: any) {
      const { container, command, timeout = 60 } = params;

      if (!isContainerRunning(container)) {
        return { content: [{ type: "text", text: `Container not running. Use sandbox_init.` }], details: {}, isError: true };
      }

      try {
        logCommand(container.slice(0, 12), command);
        const out = dockerExec(container, command, timeout * 1000);

        const containers = loadContainers();
        const info = containers[container];
        if (info) {
          info.lastActivity = new Date().toISOString();
          saveContainers(containers);
        }

        // 保存进度
        const progress = loadProgress();
        progress.commands.push({ cmd: command, ts: new Date().toISOString(), container: container.slice(0, 12) });
        if (progress.commands.length > 50) progress.commands.shift();

        for (const line of out.split("\n")) {
          if (/flag\{.*\}/i.test(line)) progress.findings.push({ type: "flag", content: line.trim() });
          else if (/password|secret|key.*[:=]/i.test(line)) progress.findings.push({ type: "cred", content: line.trim() });
          else if (/[A-Za-z0-9_]{6,}[Kk]ey|[Kk]ey[A-Za-z0-9_]{6,}/i.test(line)) progress.findings.push({ type: "key_string", content: line.trim() });
          else if (/encrypt|decrypt|cipher|aes|rsa|xor.*key/i.test(line)) progress.findings.push({ type: "crypto_hint", content: line.trim() });
        }

        if (command.includes("r2")) progress.currentStep = "radare2";
        else if (command.includes("gdb")) progress.currentStep = "debugging";
        else if (command.includes("strings")) progress.currentStep = "strings";

        saveProgress(progress);

        return { content: [{ type: "text", text: out || "(no output)" }], details: { container, command } };
      } catch (err: any) {
        return { content: [{ type: "text", text: `Failed: ${err.message}` }], details: {}, isError: true };
      }
    },
  };
}

export function createSandboxInstallTool() {
  return {
    name: "sandbox_install",
    label: "Install Tools",
    description: "在沙箱安装工具",
    parameters: Type.Object({
      container: Type.String({ description: "容器 ID" }),
      packages: Type.String({ description: "包名" }),
    }),
    async execute(toolCallId: string, params: any) {
      try {
        const out = dockerExec(params.container, `sudo apt-get update -qq && sudo apt-get install -y ${params.packages}`, 300000);
        return { content: [{ type: "text", text: `Installed: ${params.packages}\n${out}` }], details: {} };
      } catch (err: any) {
        return { content: [{ type: "text", text: `Failed: ${err.message}` }], details: {}, isError: true };
      }
    },
  };
}

export function createSandboxListTool() {
  return {
    name: "sandbox_list",
    label: "List Sandboxes",
    description: "列出活动容器",
    parameters: Type.Object({}),
    async execute() {
      const containers = loadContainers();
      const active: ContainerInfo[] = [];
      for (const [id, info] of Object.entries(containers)) {
        if (isContainerRunning(id)) {
          active.push(info);
        } else {
          delete containers[id];
        }
      }
      saveContainers(containers);

      if (active.length === 0) return { content: [{ type: "text", text: "No active sandboxes." }], details: {} };

      return {
        content: [{ type: "text", text: active.map((c, i) => `${i + 1}. ${c.id.slice(0, 12)} | ${basename(c.file)} | ${c.workspace}`).join("\n") }],
        details: { count: active.length },
      };
    },
  };
}

export function createSandboxReconnectTool() {
  return {
    name: "sandbox_reconnect",
    label: "Reconnect Sandbox",
    description: "重连容器，查看进度",
    parameters: Type.Object({ container: Type.String({ description: "容器 ID" }) }),
    async execute(toolCallId: string, params: any) {
      const containers = loadContainers();
      const info = containers[params.container];
      if (!info) return { content: [{ type: "text", text: "Container not found." }], details: {}, isError: true };

      const workspace = getSharedWorkspace();
      const progress = loadProgress();
      let summary = `Step: ${progress.currentStep || "N/A"}\nCommands: ${progress.commands.length}\nFindings: ${progress.findings.length}`;

      if (progress.findings.length > 0) {
        summary += "\n\nKey findings:\n" + progress.findings.slice(0, 10).map((f: any) => `- [${f.type}] ${f.content.slice(0, 80)}`).join("\n");
      }

      return {
        content: [{ type: "text", text: `Reconnected: ${params.container.slice(0, 12)}\nFile: ${info.file}\nWorkspace: ${workspace}\n\n${summary}` }],
        details: { workspace },
      };
    },
  };
}

export function createSandboxCleanupTool() {
  return {
    name: "sandbox_cleanup",
    label: "Cleanup Sandbox",
    description: "删除容器",
    parameters: Type.Object({ container: Type.String({ description: "容器 ID" }) }),
    async execute(toolCallId: string, params: any) {
      try {
        dockerRm(params.container);
        const containers = loadContainers();
        delete containers[params.container];
        saveContainers(containers);
        return { content: [{ type: "text", text: `Removed ${params.container.slice(0, 12)}` }], details: {} };
      } catch (err: any) {
        return { content: [{ type: "text", text: `Failed: ${err.message}` }], details: {}, isError: true };
      }
    },
  };
}
