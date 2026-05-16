---
name: rev-symbol
description: 通过代码模式、字符串、常量和交叉引用恢复函数符号名。当面对 stripped 二进制中大量 sub_XXXXX/fcn.XXXXX 函数需要命名时使用。
---

# Symbol Recovery

分析函数代码特征来恢复/识别函数符号名。

## Gotchas

- IDA FLIRT 签名能自动识别大部分 libc 函数——先跑 FLIRT 再手动
- 不要给每个函数都命名——只命名对理解逻辑有帮助的关键函数
- 字符串引用是最可靠的命名线索（`"error: invalid key"` → 函数可能是 `validate_key`）
- 常量特征（如 `0x5A827999` = SHA-1, `0x67452301` = MD5 init）可直接识别加密函数
- Go/Rust 二进制即使 stripped 也有丰富的类型信息——用专门工具（GoReSym/rust-demangler）

## Workflow

1. **IDA `survey_binary`** → 看函数总数和已命名比例
2. **IDA FLIRT** → 自动识别标准库（如果是静态链接）
3. **字符串引用法**：`xrefs_to` 有意义的字符串 → 命名引用它的函数
4. **常量特征法**：搜索已知加密/哈希常量 → 命名对应函数
5. **调用图法**：`callgraph` 从已知函数向上/向下传播名称
6. **导入引用法**：调用 `malloc`+`free` 的函数可能是构造/析构器
7. **IDA `rename`** → 批量应用命名

## 命名规范

| 线索 | 命名模式 |
|------|----------|
| 引用 "error" 字符串 | `handle_error` / `validate_xxx` |
| 调用 crypto 常量 | `aes_encrypt` / `sha256_update` |
| 接收 fd 参数 + read/write | `io_handler` / `process_request` |
| 大量比较 + 返回 0/1 | `check_xxx` / `verify_xxx` |
| 调用 malloc + 初始化字段 | `create_xxx` / `init_xxx` |
| 调用 free | `destroy_xxx` / `cleanup_xxx` |

保存命名结果到 `/workspace/cache/<basename>.symbols.txt`（格式：`addr name`）

## When to Pivot

- 符号恢复完成 → 回到 re-static 继续分析逻辑
- 需要运行时确认函数行为 → re-dynamic
