#!/bin/bash
# 快速测试脚本: /data_types 端点
# 用法: ./test_data_types.sh

BASE_URL="http://127.0.0.1:8080"

echo "======================================"
echo "GhidraMCP 数据类型端点测试"
echo "======================================"
echo ""

# 测试 1: 基本功能测试
echo "测试 1: 基本功能测试 (获取前 10 个数据类型)"
echo "命令: curl \"$BASE_URL/data_types?offset=0&limit=10\""
echo "---"
curl -s "$BASE_URL/data_types?offset=0&limit=10"
echo ""
echo ""

# 测试 2: 分页测试
echo "测试 2: 分页测试"
echo "命令: 第一页 (offset=0, limit=5)"
echo "---"
curl -s "$BASE_URL/data_types?offset=0&limit=5"
echo ""
echo "命令: 第二页 (offset=5, limit=5)"
echo "---"
curl -s "$BASE_URL/data_types?offset=5&limit=5"
echo ""
echo ""

# 测试 3: 边界情况测试
echo "测试 3: 边界情况测试 (offset 超出范围)"
echo "命令: curl \"$BASE_URL/data_types?offset=999999&limit=100\""
echo "---"
RESULT=$(curl -s "$BASE_URL/data_types?offset=999999&limit=100")
if [ -z "$RESULT" ]; then
    echo "(空响应 - 正确)"
else
    echo "$RESULT"
fi
echo ""
echo ""

# 测试 4: 默认参数测试
echo "测试 4: 默认参数测试 (无参数)"
echo "命令: curl \"$BASE_URL/data_types\""
echo "返回的数据类型数量:"
curl -s "$BASE_URL/data_types" | wc -l
echo ""
echo ""

# 测试 5: 路径格式验证
echo "测试 5: 路径格式验证 (前 20 个数据类型)"
echo "命令: curl \"$BASE_URL/data_types?offset=0&limit=20\""
echo "---"
curl -s "$BASE_URL/data_types?offset=0&limit=20"
echo ""
echo ""

# 测试 6: 性能测试 (获取 1000 个数据类型)
echo "测试 6: 性能测试 (获取 1000 个数据类型)"
echo "命令: time curl \"$BASE_URL/data_types?offset=0&limit=1000\""
echo "---"
time curl -s "$BASE_URL/data_types?offset=0&limit=1000" > /dev/null
echo ""

echo "======================================"
echo "测试完成!"
echo "======================================"
