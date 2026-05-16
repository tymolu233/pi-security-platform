// .pi/extensions/security-platform/utils/workspace.ts
import { existsSync, readFileSync, writeFileSync, mkdirSync, copyFileSync, readdirSync, statSync, cpSync } from "node:fs";
import { join, basename } from "node:path";
import { winPath } from "./docker.js";
import { isContainerRunning } from "./docker.js";
import type { ContainerInfo, Progress } from "../types.js";

const CONTAINER_STORE = join(process.env.HOME || process.env.USERPROFILE || "/tmp", ".pi-sandbox-containers.json");

// 获取或创建工作文件夹（在当前目录）
export function getWorkspace(cwd?: string): string {
  const baseDir = cwd || process.cwd();
  const workspace = join(baseDir, ".security-workspace");

  if (!existsSync(workspace)) {
    mkdirSync(workspace, { recursive: true });
    mkdirSync(join(workspace, "targets"), { recursive: true });
    mkdirSync(join(workspace, "output"), { recursive: true });
    mkdirSync(join(workspace, "scripts"), { recursive: true });
    mkdirSync(join(workspace, "logs"), { recursive: true });
    mkdirSync(join(workspace, "cache"), { recursive: true });
    writeFileSync(join(workspace, "README.md"), "# Security Workspace\n\nAuto-created workspace for security analysis.\n");
    writeFileSync(join(workspace, "logs", "session.log"), `[${new Date().toISOString()}] Workspace created at ${workspace}\n`);
  } else if (!existsSync(join(workspace, "cache"))) {
    // Backfill cache/ for workspaces created before this dir was added
    mkdirSync(join(workspace, "cache"), { recursive: true });
  }

  return workspace;
}

// 兼容旧接口
export function getSharedWorkspace(): string {
  return getWorkspace();
}

export function addToWorkspace(filePath: string, filesToCopy?: string[], cwd?: string): string {
  const workspace = getWorkspace(cwd);
  const fileName = basename(filePath);
  const destFile = join(workspace, "targets", fileName);

  if (!existsSync(destFile)) {
    copyFileSync(filePath, destFile);
  }

  if (filesToCopy) {
    for (const f of filesToCopy) {
      const src = f.startsWith("/") || f.match(/^[A-Z]:\\/i) ? f : join(filePath, "..", f);
      const dest = join(workspace, "targets", basename(f));
      if (existsSync(src) && !existsSync(dest)) {
        try {
          const st = statSync(src);
          if (st.isDirectory()) {
            cpSync(src, dest, { recursive: true });
          } else {
            copyFileSync(src, dest);
          }
        } catch {}
      }
    }
  }

  logCommand("system", `Added file: ${fileName}`);
  return workspace;
}

export function logCommand(container: string, command: string): void {
  const workspace = getWorkspace();
  const logFile = join(workspace, "logs", "commands.log");
  writeFileSync(logFile, `[${new Date().toISOString()}] [${container}] $ ${command}\n`, { flag: "a" });
}

export function saveProgress(progress: Progress): void {
  const workspace = getWorkspace();
  writeFileSync(join(workspace, "output", "progress.json"), JSON.stringify(progress, null, 2));
}

export function loadProgress(): Progress {
  const workspace = getWorkspace();
  const path = join(workspace, "output", "progress.json");
  if (existsSync(path)) {
    return JSON.parse(readFileSync(path, "utf-8"));
  }
  return { findings: [], commands: [], currentStep: "" };
}

export function loadContainers(): Record<string, ContainerInfo> {
  try {
    if (existsSync(CONTAINER_STORE)) {
      return JSON.parse(readFileSync(CONTAINER_STORE, "utf-8"));
    }
  } catch {}
  return {};
}

export function saveContainers(containers: Record<string, ContainerInfo>): void {
  try {
    writeFileSync(CONTAINER_STORE, JSON.stringify(containers, null, 2));
  } catch {}
}

export function getContainerForFile(file: string): string | null {
  const containers = loadContainers();
  for (const [id, info] of Object.entries(containers)) {
    if (info.file === file && info.status === "running") {
      try {
        if (isContainerRunning(id)) return id;
        containers[id].status = "stopped";
        saveContainers(containers);
      } catch {}
    }
  }
  return null;
}
