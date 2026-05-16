---
name: rev-struct
description: 通过分析内存访问模式恢复数据结构定义。当 IDA decompile 输出中有大量 offset 访问（如 *(a1+0x18)）需要还原为有意义的结构体时使用。
---

# Structure Recovery

从函数的内存访问模式中恢复结构体定义。

## Gotchas

- 不要猜测字段类型——从实际访问宽度（byte/word/dword/qword）和使用上下文推断
- 同一 offset 在不同函数中可能有不同语义（union）——检查所有 xref
- IDA 的 `infer_types` 能自动恢复大部分简单结构——先试 IDA 再手动
- 对齐（padding）会导致 offset 不连续——注意 4/8 字节对齐间隙

## Workflow

1. **IDA `decompile`** 目标函数 → 识别 `*(base + offset)` 模式
2. **IDA `xrefs_to`** base 参数 → 找所有使用该结构的函数
3. **收集 offset 表**：每个 offset 的访问宽度、读/写、上下文
4. **IDA `infer_types`** → 让 IDA 自动尝试
5. **手动补全**：IDA 没识别的字段，根据 offset 表声明
6. **IDA `declare_type`** → 写入 idb
7. **重新 decompile** → 验证结构体是否让代码更可读

## 输出格式

```c
struct target_struct {
    int field_0x00;        // accessed as dword, compared with 0
    void *field_0x08;      // pointer, passed to free()
    char name[32];         // accessed byte-by-byte, null-terminated
    int flags;             // bitmask operations observed
};
```

保存到 `/workspace/cache/<basename>.structs.h`

## When to Pivot

- 结构体恢复完成，需要理解算法逻辑 → 回到 re-static 主流程
- 结构体是网络协议 → 可能需要 pcap 对照（forensics-analyst）
