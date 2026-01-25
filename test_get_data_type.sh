#!/bin/bash

# 测试脚本: 获取特定数据类型详情
# 使用方法: ./test_get_data_type.sh

BASE_URL="http://127.0.0.1:8080"

echo "========================================"
echo "测试 Task 1.2: 获取特定数据类型详情"
echo "========================================"
echo ""

# 测试 1: 内置类型 int
echo "测试 1: 获取内置类型 int"
echo "请求: GET $BASE_URL/data_types/int"
echo "响应:"
curl -s "$BASE_URL/data_types/int" | jq . 2>/dev/null || curl -s "$BASE_URL/data_types/int"
echo ""
echo ""

# 测试 2: 内置类型 float
echo "测试 2: 获取内置类型 float"
echo "请求: GET $BASE_URL/data_types/float"
echo "响应:"
curl -s "$BASE_URL/data_types/float" | jq . 2>/dev/null || curl -s "$BASE_URL/data_types/float"
echo ""
echo ""

# 测试 3: 内置类型 char
echo "测试 3: 获取内置类型 char"
echo "请求: GET $BASE_URL/data_types/char"
echo "响应:"
curl -s "$BASE_URL/data_types/char" | jq . 2>/dev/null || curl -s "$BASE_URL/data_types/char"
echo ""
echo ""

# 测试 4: 列出所有可用的数据类型
echo "测试 4: 列出所有可用的数据类型 (前 10 个)"
echo "请求: GET $BASE_URL/data_types?offset=0&limit=10"
echo "响应:"
curl -s "$BASE_URL/data_types?offset=0&limit=10"
echo ""
echo ""

# 测试 5: 测试不存在的类型
echo "测试 5: 获取不存在的类型"
echo "请求: GET $BASE_URL/data_types/NonExistentType12345"
echo "响应:"
curl -s "$BASE_URL/data_types/NonExistentType12345" | jq . 2>/dev/null || curl -s "$BASE_URL/data_types/NonExistentType12345"
echo ""
echo ""

# 测试 6: 测试带路径的类型 (如果存在)
echo "测试 6: 尝试获取带路径的类型"
echo "请求: GET $BASE_URL/data_types/void"
echo "响应:"
curl -s "$BASE_URL/data_types/void" | jq . 2>/dev/null || curl -s "$BASE_URL/data_types/void"
echo ""
echo ""

# 测试 7: 测试指针类型
echo "测试 7: 测试指针类型"
echo "请求: GET $BASE_URL/data_types/pointer"
echo "响应:"
curl -s "$BASE_URL/data_types/pointer" | jq . 2>/dev/null || curl -s "$BASE_URL/data_types/pointer"
echo ""
echo ""

echo "========================================"
echo "测试完成"
echo "========================================"
echo ""
echo "注意事项:"
echo "1. 如果看到 'Connection refused',请确认 Ghidra 正在运行且插件已启动"
echo "2. 如果看到 'No program loaded',请在 Ghidra 中打开一个程序"
echo "3. 如果有 jq 命令,JSON 输出会被格式化;否则显示原始输出"
echo "4. 要测试结构体或枚举,需要先在 Ghidra 中定义相应的数据类型"
