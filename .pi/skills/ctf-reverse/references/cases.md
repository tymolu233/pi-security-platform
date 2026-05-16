# CTF 逆向完整案例集

## 案例 1: XOR 加密逆向

### 场景
二进制使用 XOR 加密 flag，需要找到密钥并解密。

### 分析流程

**Step 1: 找加密函数**
```bash
r2 -q -c "aaa; afl" binary | grep -i "encrypt\|xor\|encode"
```

**Step 2: 分析 XOR 逻辑**
```python
import r2pipe
r2 = r2pipe.open("./binary")
r2.cmd("aaa")

# 找到 XOR 循环
code = r2.cmd("pdf @ sym.encrypt")
# 分析:
# mov al, [rsi]      ; 读取明文
# xor al, cl         ; XOR 密钥
# mov [rdi], al      ; 存储密文
# inc rsi
# inc rdi
# loop
```

**Step 3: 提取密文**
```bash
r2 -q -c "px 64 @ 0x404000" binary
# 获取加密后的 flag
```

**Step 4: 解密**
```python
# 方法 1: 已知明文攻击
ciphertext = bytes.fromhex("...")
known_plaintext = b"flag{"
key = bytes(c ^ p for c, p in zip(ciphertext[:5], known_plaintext))
# 扩展密钥
full_key = (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]
plaintext = bytes(c ^ k for c, k in zip(ciphertext, full_key))
print(plaintext)

# 方法 2: 暴力搜索单字节密钥
for key in range(256):
    result = bytes(b ^ key for b in ciphertext)
    if b"flag{" in result:
        print(f"Key: {key}, Flag: {result}")
        break
```

---

## 案例 2: 反调试 + 时间检测绕过

### 场景
程序使用 ptrace + clock_gettime 检测调试器。

### 分析流程

**Step 1: 识别反调试**
```bash
r2 -q -c "aaa; /x 48c7c70000000048c7c01a0000000f05" binary
# ptrace(PTRACE_TRACEME, 0, 0, 0)

r2 -q -c "aaa; /x 48c7c70000000048c7c0e40000000f05" binary
# clock_gettime(CLOCK_MONOTONIC, ...)
```

**Step 2: 使用 Frida 绕过**
```javascript
// 绕过 ptrace
var ptrace = Module.findExportByName(null, 'ptrace');
Interceptor.replace(ptrace, new NativeCallback(function(request, pid, addr, data) {
    return 0;
}, 'long', ['int', 'int', 'pointer', 'pointer']));

// 绕过时间检测
var clock_gettime = Module.findExportByName(null, 'clock_gettime');
Interceptor.attach(clock_gettime, {
    onLeave: function(retval) {
        // 修改返回的时间
        var timespec = this.context.rdi;
        timespec.writeU32(0x5f000000);  // 固定时间
    }
});
```

**Step 3: 提取 flag**
```bash
frida -l bypass.js ./binary
# 程序正常执行，输出 flag
```

---

## 案例 3: C++ 虚表逆向

### 场景
C++ 程序使用多态，flag 校验逻辑在虚函数中。

### 分析流程

**Step 1: 找 vtable**
```bash
r2 -q -c "aaa; iz" binary | grep "vtable"
# 或
r2 -q -c "px 32 @ 0x404000" binary
```

**Step 2: 分析类结构**
```python
import r2pipe
r2 = r2pipe.open("./binary")
r2.cmd("aaa")

# 找 vtable
vtable_addr = 0x404020

# 读取虚函数
for i in range(5):
    func_ptr = int(r2.cmd(f"pq 8 @ {vtable_addr + i*8}"), 16)
    if func_ptr > 0x400000:
        name = r2.cmd(f"afn @ {func_ptr}").strip()
        print(f"vfunc[{i}] = {name}")

# 输出:
# vfunc[0] = sym.Base::~Base
# vfunc[1] = sym.Base::check
# vfunc[2] = sym.Derived::check  # 覆盖了 check
```

**Step 3: 分析校验逻辑**
```bash
r2 -q -c "pdf @ sym.Derived::check" binary
# 分析汇编代码
# 通常是比较输入和预期值
```

**Step 4: 提取 flag**
```python
# 从比较指令中提取预期值
expected = [0x66, 0x6c, 0x61, 0x67, 0x7b, ...]
flag = ''.join(chr(b) for b in expected)
print(flag)
```

---

## 案例 4: 自定义编码逆向

### 场景
二进制使用自定义编码算法（非标准 base64/xxtea）。

### 分析流程

**Step 1: 识别编码函数**
```bash
r2 -q -c "aaa; afl" binary | grep -i "encode\|decode\|transform"
```

**Step 2: 分析编码逻辑**
```python
import r2pipe
r2 = r2pipe.open("./binary")
r2.cmd("aaa")

# 分析 encode 函数
code = r2.cmd("pdf @ sym.encode")
# 识别:
# 1. 替换表 (S-box)
# 2. 位操作 (shift, rotate)
# 3. 查表操作
```

**Step 3: 逆向解码**
```python
# 如果是替换表
encode_table = [0x3e, 0x3f, 0x37, 0x38, ...]
decode_table = [0] * 256
for i, v in enumerate(encode_table):
    decode_table[v] = i

def decode(encoded):
    return bytes(decode_table[b] for b in encoded)

# 如果是位操作
def decode(ciphertext):
    result = bytearray()
    for b in ciphertext:
        # 逆操作
        b = ((b >> 3) | (b << 5)) & 0xff  # rotate right 3
        b ^= 0x5a  # XOR
        result.append(b)
    return bytes(result)
```

---

## 案例 5: 状态机逆向

### 场景
程序使用状态机处理输入，需要找到正确状态序列。

### 分析流程

**Step 1: 识别状态机**
```bash
r2 -q -c "aaa; afl" binary | grep -i "state\|transition\|handler"
```

**Step 2: 提取状态转移表**
```python
import r2pipe
r2 = r2pipe.open("./binary")
r2.cmd("aaa")

# 状态转移表通常在数据段
state_table_addr = 0x404000
states = {}

for i in range(10):
    addr = state_table_addr + i * 16
    data = r2.cmd(f"px 16 @ {addr}").split()
    states[i] = {
        'next_state': int(data[0], 16),
        'check_char': chr(int(data[1], 16)),
        'handler': int(data[2] + data[3], 16),
    }
```

**Step 3: 求解正确输入**
```python
# 从最终状态反推
def solve(states, target_state):
    path = []
    current = target_state
    
    while current != 0:
        for state_id, state in states.items():
            if state['next_state'] == current:
                path.append(state['check_char'])
                current = state_id
                break
    
    return ''.join(reversed(path))

flag = solve(states, 9)
print(f"Flag: {flag}")
```

---

## 案例 6: 混淆代码简化

### 场景
程序使用不透明谓词和垃圾代码混淆。

### 分析流程

**Step 1: 使用 angr 简化**
```python
import angr
import claripy

p = angr.Project('./binary')
simgr = p.factory.simgr()

# 探索所有路径
simgr.explore()

# 找到成功路径
for state in simgr.found:
    # 获取约束
    constraints = state.solver.constraints
    print(f"Path constraints: {len(constraints)}")
```

**Step 2: 使用符号执行求解**
```python
# 创建符号输入
input_bytes = claripy.BVS('input', 8 * 32)

# 模拟执行
state = p.factory.entry_state()
simgr = p.factory.simgr(state)

# 设置目标
simgr.explore(find=0x401234)  # 成功地址

if simgr.found:
    found = simgr.found[0]
    # 求解输入
    solution = found.solver.eval(input_bytes)
    print(f"Solution: {bytes.fromhex(hex(solution)[2:])}")
```

---

## 案例 7: Shellcode 分析

### 场景
提取的 shellcode，需要理解功能。

### 分析流程

**Step 1: 反汇编**
```python
from capstone import *

shellcode = b"\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"

md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(shellcode, 0x1000):
    print(f"0x{i.address:x}: {i.mnemonic} {i.op_str}")
```

**Step 2: 模拟执行**
```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x1000, 0x1000)
mu.mem_write(0x1000, shellcode)

# 设置栈
mu.mem_map(0x700000, 0x1000)
mu.reg_write(UC_X86_REG_RSP, 0x700000 + 0x1000)

# 执行
mu.emu_start(0x1000, 0x1000 + len(shellcode))
```

**Step 3: 提取字符串**
```python
# 从 shellcode 中提取字符串引用
import re

# 找到 /bin/sh 的编码
# 0x2f62696e2f2f7368 = "/bin//sh"
binsh = 0x2f62696e2f2f7368
print(binsh.to_bytes(8, 'little'))
```

---

## 案例 8: Python 字节码逆向

### 场景
Python 编译的 .pyc 文件，需要还原源码。

### 分析流程

**Step 1: 反编译**
```bash
# 使用 uncompyle6
uncompyle6 malware.pyc > malware.py

# 如果失败，使用 decompyle3
decompyle3 malware.pyc > malware.py
```

**Step 2: 分析字节码**
```python
import dis
import marshal

# 加载 .pyc
with open("malware.pyc", "rb") as f:
    f.read(16)  # 跳过头部
    code = marshal.load(f)

# 反汇编
dis.dis(code)
```

**Step 3: 手动分析**
```python
# 如果自动反编译失败，手动分析字节码
import opcode

def analyze_code(code):
    bytecode = list(code.co_code)
    i = 0
    while i < len(bytecode):
        op = bytecode[i]
        name = opcode.opname[op]
        
        if op >= opcode.HAVE_ARGUMENT:
            arg = bytecode[i+1] | (bytecode[i+2] << 8)
            print(f"{i:4d} {name:20s} {arg}")
            i += 3
        else:
            print(f"{i:4d} {name:20s}")
            i += 1
```

---

## 分析速查表

| 场景 | 首选工具 | 备选方案 |
|------|---------|---------|
| 简单 XOR | 频率分析 | 暴力搜索 |
| 自定义编码 | 逆向算法 | angr 符号执行 |
| 反调试 | Frida bypass | patch 二进制 |
| C++ 虚表 | r2 + Ghidra | 手动分析 |
| 状态机 | 提取转移表 | Z3 求解 |
| 混淆代码 | angr 简化 | miasm |
| Shellcode | capstone + unicorn | 手动分析 |
| Python 字节码 | uncompyle6 | dis 模块 |
