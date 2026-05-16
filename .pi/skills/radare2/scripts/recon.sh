#!/bin/bash
# radare2 侦察脚本 (Linux/Docker 版本)
# 用法: bash recon.sh <target_path> [--analysis]

set -e

TARGET="$1"
RUN_ANALYSIS="${2:-}"
STRINGS_LIMIT=40
IMPORTS_LIMIT=80

if [ -z "$TARGET" ]; then
    echo "用法: bash recon.sh <target_path> [--analysis]"
    exit 1
fi

if [ ! -f "$TARGET" ]; then
    echo "错误: 文件不存在: $TARGET"
    exit 1
fi

echo "=== 基本信息 ==="
rabin2 -I -- "$TARGET"

echo ""
echo "=== 节区 ==="
rabin2 -S -- "$TARGET"

echo ""
echo "=== 导入 ==="
rabin2 -i -- "$TARGET" | head -n "$IMPORTS_LIMIT"

echo ""
echo "=== 导出 ==="
rabin2 -E -- "$TARGET"

echo ""
echo "=== 字符串 ==="
rabin2 -zz -- "$TARGET" | head -n "$STRINGS_LIMIT"

if [ "$RUN_ANALYSIS" = "--analysis" ]; then
    echo ""
    echo "=== 函数与入口分析 ==="
    r2 -A -q -c 's entry0;afl;iz;ii;q' -- "$TARGET"
fi
