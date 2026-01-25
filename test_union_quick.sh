#!/bin/bash

# 联合体 (Union) 快速测试脚本
# 用于快速验证基本的联合体功能

set -e

GHIDRA_SERVER="${GHIDRA_SERVER:-http://127.0.0.1:8080}"

echo "========================================"
echo "联合体快速测试"
echo "Ghidra 服务器: $GHIDRA_SERVER"
echo "========================================"
echo ""

# 测试 1: 最简单的联合体
echo "测试 1: 创建简单的 IntFloat 联合体"
response=$(curl -s -X POST \
    "$GHIDRA_SERVER/data_types/union" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "IntFloat",
        "categoryPath": "/Test",
        "fields": [
            {"name": "asInt", "dataType": "/int", "length": 4},
            {"name": "asFloat", "dataType": "/float", "length": 4}
        ]
    }')
echo "响应: $response"
echo ""

# 测试 2: 验证创建的联合体
echo "测试 2: 获取 IntFloat 联合体详情"
response=$(curl -s "$GHIDRA_SERVER/data_types/Test/IntFloat")
echo "响应: $response"
echo ""

# 测试 3: 列出所有类型
echo "测试 3: 列出所有数据类型"
response=$(curl -s "$GHIDRA_SERVER/data_types?offset=0&limit=20")
echo "$response" | grep -E "(IntFloat|Union)"
echo ""

echo "✅ 快速测试完成!"
