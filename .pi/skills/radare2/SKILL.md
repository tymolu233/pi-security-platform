---
name: radare2
description: radare2/r2 命令行二进制分析。当用户要用 r2 分析 PE/ELF/Mach-O/DEX/WASM 文件、使用 rabin2/rasm2/radiff2、做命令行反汇编/patch/diffing/hex 检查、或写 r2pipe 脚本时使用。如果用户要 IDA/Hex-Rays 风格分析，优先用 ida-reverse。
---

# radare2

命令行二进制分析。在本项目中 r2 是 **IDA 的备选**——当 IDA 不可用或需要批量脚本化时使用。

## Gotchas

- 不要一上来就 `aaaa`（全量分析）——大文件会卡很久，先 `aaa` 或定向分析
- `r2 -w` 会直接修改原文件——默认只读打开，修改前确认
- r2ghidra 的 decompile 质量远不如 IDA Hex-Rays——复杂函数优先用 IDA
- Windows 下 `.sdb` 缺失告警通常不影响分析，不要因此判定失败
- 静态链接 stripped 二进制 r2 识别不了 libc 函数——这种情况必须用 IDA FLIRT

## Docker Sandbox 规则

**r2 全部在 Docker 中执行**。使用 `recon.sh` 做第一轮侦察。

```
sandbox_init(path="binary")
sandbox_exec(cmd="bash /opt/scripts/recon.sh /workspace/targets/binary")
sandbox_exec(cmd="bash /opt/scripts/recon.sh /workspace/targets/binary --analysis")
```

## 常用命令速查

| 命令 | 说明 |
|------|------|
| `rabin2 -I file` | 基本信息（arch/bits/endian） |
| `rabin2 -S file` | 节区 |
| `rabin2 -i file` | 导入 |
| `rabin2 -E file` | 导出 |
| `rabin2 -z file` | 字符串（.rodata） |
| `rabin2 -zz file` | 全文件字符串 |
| `r2 -q -c 'aaa; afl' file` | 函数列表 |
| `r2 -q -c 'aaa; pdf @ main' file` | 反汇编 main |
| `r2 -q -c 'aaa; pdg @ main' file` | r2ghidra decompile |
| `r2 -q -c 'aaa; axt @ sym.imp.strcmp' file` | 交叉引用 |
| `rasm2 -a x86 -b 64 'nop'` | 汇编指令 |
| `radiff2 -c file1 file2` | 二进制 diff |

## When to Pivot

- 需要高质量 decompile/类型恢复/xref 深度分析 → 用 IDA via MCP
- 需要动态调试 → 用 gdb（sandbox）
- 需要符号执行 → 用 angr（sandbox）

## Additional Resources

- [references/cheatsheet.md](references/cheatsheet.md) — 完整命令速查表、场景模板
- [scripts/](scripts/) — recon 脚本
