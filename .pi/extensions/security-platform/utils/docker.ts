// .pi/extensions/security-platform/utils/docker.ts
import { execSync } from "node:child_process";
import type { ContainerInfo } from "../types.js";

export function winPath(p: string): string {
  return process.platform === "win32" ? p.replace(/\\/g, "/") : p;
}

export function getShell() {
  return process.platform === "win32" ? "powershell" : "/bin/sh";
}

export function dockerExec(containerId: string, command: string, timeout = 60000): string {
  const shell = getShell();
  if (process.platform === "win32") {
    // PowerShell: use single-quoted here-string to avoid all escaping issues
    // Pass command via stdin to docker exec bash
    const b64 = Buffer.from(command, "utf-8").toString("base64");
    return execSync(
      `docker exec ${containerId} bash -c "echo ${b64} | base64 -d | bash"`,
      { timeout, encoding: "utf-8", shell, maxBuffer: 2 * 1024 * 1024 } as any
    );
  }
  // Unix: straightforward
  const escaped = command.replace(/'/g, "'\\''");
  return execSync(`docker exec ${containerId} bash -c '${escaped}'`, {
    timeout,
    encoding: "utf-8",
    shell,
    maxBuffer: 2 * 1024 * 1024,
  } as any);
}

export function dockerInspect(containerId: string, format: string): string {
  const shell = getShell();
  if (process.platform === "win32") {
    // PowerShell: double-quote the format, escape inner braces
    return execSync(`docker inspect -f "${format}" ${containerId}`, {
      encoding: "utf-8",
      stdio: "pipe",
      shell,
    } as any).trim();
  }
  return execSync(`docker inspect -f '${format}' ${containerId}`, {
    encoding: "utf-8",
    stdio: "pipe",
    shell,
  } as any).trim();
}

export function isContainerRunning(containerId: string): boolean {
  try {
    return dockerInspect(containerId, "{{.State.Running}}") === "true";
  } catch {
    return false;
  }
}

export function dockerRm(containerId: string): void {
  const shell = getShell();
  execSync(`docker rm -f ${containerId}`, { encoding: "utf-8", shell } as any);
}
