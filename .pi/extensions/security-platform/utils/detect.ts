// .pi/extensions/security-platform/utils/detect.ts
import { existsSync, openSync, readSync, closeSync, statSync } from "node:fs";
import { extname } from "node:path";
import type { TargetType } from "../types.js";

const BINARY_EXTENSIONS = [".exe", ".elf", ".bin", ".so", ".dll", ".pyc", ".apk", ".dex", ".wasm", ".dat", ".enc"];
const FORENSICS_EXTENSIONS = [".pcap", ".pcapng", ".dmp", ".img", ".raw", ".vmem", ".mem", ".e01", ".aff"];
const CRYPTO_EXTENSIONS = [".enc", ".cipher", ".gpg", ".pgp", ".asc"];

export function detectTargetType(target: string): TargetType {
  if (/^https?:\/\//i.test(target)) return "url";
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target)) return "ip";
  if (target.includes("/") || target.includes("\\") || target.includes(".")) {
    const ext = extname(target).toLowerCase();
    if (BINARY_EXTENSIONS.includes(ext)) return "file";
    if (existsSync(target)) return "file";
  }
  if (/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(target)) return "domain";
  if (existsSync(target)) return "file";
  return "unknown";
}

export function extractHost(target: string): string {
  return target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
}

export function recommendAgent(target: string, targetType: TargetType): string {
  if (targetType === "file") {
    const ext = extname(target).toLowerCase();
    if (FORENSICS_EXTENSIONS.includes(ext)) return "forensics-analyst";
    if (CRYPTO_EXTENSIONS.includes(ext)) return "crypto-analyst";
    return "re-triage";
  }
  if (targetType === "url" || targetType === "domain") return "web-pentester";
  if (targetType === "ip") return "recon-specialist";
  return "recon-specialist";
}

// Cross-platform replacement for `file` command. Reads magic bytes via Node fs.
export function quickFileType(filePath: string): string {
  try {
    const stat = statSync(filePath);
    const headerSize = Math.min(64, stat.size);
    if (headerSize < 4) return `tiny file (${stat.size} bytes)`;
    const buf = Buffer.alloc(headerSize);
    const fd = openSync(filePath, "r");
    readSync(fd, buf, 0, headerSize, 0);
    closeSync(fd);

    // ELF
    if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
      const bits = buf[4] === 1 ? "32-bit" : buf[4] === 2 ? "64-bit" : "?";
      const endian = buf[5] === 1 ? "LSB" : buf[5] === 2 ? "MSB" : "?";
      const types: Record<number, string> = { 1: "REL", 2: "EXEC", 3: "DYN (shared object)", 4: "CORE" };
      const elfType = buf.length >= 18 ? types[buf.readUInt16LE(16)] || `type ${buf.readUInt16LE(16)}` : "";
      const archMap: Record<number, string> = { 0x03: "x86", 0x3e: "x86_64", 0x28: "ARM", 0xb7: "AArch64", 0x08: "MIPS", 0xf3: "RISC-V" };
      const arch = buf.length >= 20 ? archMap[buf.readUInt16LE(18)] || `arch 0x${buf.readUInt16LE(18).toString(16)}` : "";
      return `ELF ${bits} ${endian} ${arch} ${elfType} (${stat.size} bytes)`.trim();
    }
    // PE/DOS MZ
    if (buf[0] === 0x4d && buf[1] === 0x5a) return `PE/DOS executable (MZ, ${stat.size} bytes)`;
    // Mach-O / Java class
    const m32 = buf.readUInt32BE(0);
    if (m32 === 0xcafebabe) {
      // Disambiguate Java class (major version >= 45) vs Mach-O fat (small nfat_arch)
      const next = buf.length >= 8 ? buf.readUInt32BE(4) : 0;
      if (next < 0x100) return `Mach-O fat binary (${next} archs, ${stat.size} bytes)`;
      return `Java class file (major ${buf.readUInt16BE(6)}, ${stat.size} bytes)`;
    }
    if (m32 === 0xfeedface) return `Mach-O 32-bit BE (${stat.size} bytes)`;
    if (m32 === 0xfeedfacf) return `Mach-O 64-bit BE (${stat.size} bytes)`;
    if (m32 === 0xcefaedfe) return `Mach-O 32-bit LE (${stat.size} bytes)`;
    if (m32 === 0xcffaedfe) return `Mach-O 64-bit LE (${stat.size} bytes)`;
    // ZIP family (APK/JAR/IPA/DOCX/...)
    if (buf[0] === 0x50 && buf[1] === 0x4b) return `ZIP archive (APK/JAR/IPA/etc, ${stat.size} bytes)`;
    // DEX
    if (buf.slice(0, 3).toString() === "dex") return `Android DEX (${stat.size} bytes)`;
    // WASM
    if (buf[0] === 0x00 && buf[1] === 0x61 && buf[2] === 0x73 && buf[3] === 0x6d) return `WebAssembly (${stat.size} bytes)`;
    // PDF
    if (buf.slice(0, 4).toString() === "%PDF") return `PDF document (${stat.size} bytes)`;
    // PCAP
    if (m32 === 0xa1b2c3d4 || m32 === 0xd4c3b2a1) return `PCAP capture (${stat.size} bytes)`;
    if (m32 === 0x0a0d0d0a) return `PCAPNG capture (${stat.size} bytes)`;
    // Python bytecode
    const m16 = buf.readUInt16LE(0);
    if ((m16 === 0x550d || m16 === 0x420d || m16 === 0xa70d || m16 === 0xee0c) && buf[2] === 0x0d && buf[3] === 0x0a) {
      return `Python bytecode (.pyc, ${stat.size} bytes)`;
    }
    // gzip
    if (buf[0] === 0x1f && buf[1] === 0x8b) return `gzip compressed (${stat.size} bytes)`;
    // 7z
    if (buf[0] === 0x37 && buf[1] === 0x7a && buf[2] === 0xbc && buf[3] === 0xaf) return `7-Zip archive (${stat.size} bytes)`;
    // RAR
    if (buf.slice(0, 4).toString() === "Rar!") return `RAR archive (${stat.size} bytes)`;
    // OpenSSL salted enc
    if (buf.slice(0, 8).toString() === "Salted__") return `OpenSSL salted encrypted data (${stat.size} bytes)`;
    // GPG
    if (buf[0] === 0x85 || buf[0] === 0x95 || buf[0] === 0x8c) return `GPG/PGP encrypted data (${stat.size} bytes)`;

    // ASCII probe
    let ascii = true;
    for (let i = 0; i < Math.min(headerSize, 32); i++) {
      const b = buf[i];
      if (!(b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126))) { ascii = false; break; }
    }
    if (ascii) return `ASCII text or data (${stat.size} bytes)`;

    return `data (${stat.size} bytes, magic 0x${m32.toString(16).padStart(8, "0")})`;
  } catch (err: any) {
    return `error reading file: ${err.message}`;
  }
}
