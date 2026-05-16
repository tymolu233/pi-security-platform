// .pi/extensions/security-platform/types.ts

export interface ContainerInfo {
  id: string;
  file: string;
  workspace: string;
  createdAt: string;
  status: "running" | "stopped";
  lastActivity: string;
}

export type TargetType = "url" | "domain" | "ip" | "file" | "unknown";

export interface Finding {
  type: string;
  content: string;
  timestamp?: string;
}

export interface Progress {
  findings: Finding[];
  commands: { cmd: string; ts: string; container?: string }[];
  currentStep: string;
}
