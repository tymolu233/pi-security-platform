---
name: ctf-pwn
description: CTF 二进制漏洞利用技术。当已有可利用的原生目标/服务，需要将内存破坏或底层原语转化为代码执行或提权时使用，包括缓冲区溢出、格式化字符串、堆利用、ROP、ret2libc、shellcode、内核利用、seccomp 绕过、沙箱逃逸。不理解二进制功能时先用 ctf-reverse；纯 web/取证/密码学问题不用本 skill。
---

# CTF Binary Exploitation (Pwn)

## Gotchas

- 不要在没 `checksec` 之前就开始写 exploit——保护机制决定整个利用策略
- PIE 二进制必须先 leak 基址，不要硬编码地址
- glibc 版本决定堆利用手法——先确认版本再选技术（2.27 vs 2.31 vs 2.35 差异巨大）
- `one_gadget` 的约束条件经常不满足——不要盲目用，先检查寄存器状态
- 本地成功远程失败 = libc 版本不同——用 `libc-database` 确认远程 libc
- FULL RELRO 下不能写 GOT——改用 `__free_hook`/`__malloc_hook`（glibc < 2.34）或 FSOP
- 不要 `sleep()` 等待竞态——用确定性同步（userfaultfd/FUSE）

## Docker Sandbox 规则

**漏洞利用必须在 Docker 中执行**。

| 环境 | 命令 |
|------|------|
| Docker | `checksec`, `ROPgadget`, `ropper`, `one_gadget`, `gdb`, `pwntools exploit`, `seccomp-tools`, `qemu` |
| 本机/IDA | 地址计算、IDA decompile 确认偏移、`stack_frame` 精确计算 |

```
sandbox_init(path="vuln")
sandbox_exec(cmd="checksec --file=/workspace/targets/vuln")
sandbox_exec(cmd="ROPgadget --binary /workspace/targets/vuln | grep 'pop rdi'")
sandbox_exec(cmd="python3 /workspace/scripts/exploit.py")
```

## Exploit Development Workflow

1. **checksec** — 确定保护（NX/PIE/RELRO/canary/FORTIFY）
2. **IDA decompile** — 确认漏洞函数、精确偏移
3. **确定漏洞类** — stack overflow / format string / heap / UAF / off-by-one
4. **选择利用策略** — 基于保护组合（见懒加载表）
5. **写 exploit** — pwntools 模板，保存到 `/workspace/scripts/<bin>.exploit.py`
6. **本地测试** — `context.log_level = 'debug'`
7. **远程适配** — 确认 libc 版本，调整偏移

## When to Pivot

- 不理解二进制功能 → `ctf-reverse`
- 受限 shell/编码谜题/沙箱语言 → `ctf-misc`
- 利用路径依赖 web 端点 → `ctf-web`
- 需要先破解密码学原语 → `ctf-crypto`

## Additional Resources（按需加载）

| 漏洞类 | 文件 |
|---|---|
| 栈溢出基础 | [overflow-basics.md](overflow-basics.md) |
| ROP + shellcode | [rop-and-shellcode.md](rop-and-shellcode.md) |
| 高级 ROP（SROP/stack pivot/seccomp） | [rop-advanced.md](rop-advanced.md) |
| 格式化字符串 | [format-string.md](format-string.md) |
| 堆利用（tcache/fastbin/unsorted） | [heap-techniques.md](heap-techniques.md), [heap-techniques-2.md](heap-techniques-2.md) |
| FSOP / FILE 结构体 | [heap-fsop.md](heap-fsop.md) |
| 内核利用 | [kernel.md](kernel.md) → [kernel-techniques.md](kernel-techniques.md) → [kernel-bypass.md](kernel-bypass.md) |
| 沙箱/seccomp 逃逸 | [sandbox-escape.md](sandbox-escape.md) |
| 高级技术 1-5 | [advanced-exploits.md](advanced-exploits.md) 到 [advanced-exploits-5.md](advanced-exploits-5.md) |
| 快速参考 | [field-notes.md](field-notes.md) |
