#!/bin/bash

# 测试枚举创建功能
# 此脚本测试 POST /data_types/enum 端点的各种场景

GHIDRA_SERVER="http://127.0.0.1:8080"
ENDPOINT="${GHIDRA_SERVER}/data_types/enum"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试计数器
TESTS_PASSED=0
TESTS_FAILED=0

# 打印函数
print_test() {
    echo -e "\n${YELLOW}========================================${NC}"
    echo -e "${YELLOW}测试: $1${NC}"
    echo -e "${YELLOW}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((TESTS_PASSED++))
}

print_failure() {
    echo -e "${RED}✗ $1${NC}"
    echo -e "${RED}  响应: $2${NC}"
    ((TESTS_FAILED++))
}

# 测试 1: 简单枚举
print_test "测试 1: 创建简单枚举 (Color)"
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Color",
    "categoryPath": "/MyTypes",
    "size": 4,
    "values": [
      {"name": "RED", "value": 0},
      {"name": "GREEN", "value": 1},
      {"name": "BLUE", "value": 2}
    ]
  }')

if [[ "$response" == "Enum created successfully" ]]; then
    print_success "简单枚举创建成功"
else
    print_failure "简单枚举创建失败" "$response"
fi

# 测试 2: 带注释的枚举
print_test "测试 2: 创建带注释的枚举 (Priority)"
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Priority",
    "categoryPath": "/System",
    "size": 4,
    "description": "任务优先级级别",
    "values": [
      {"name": "LOW", "value": 0, "comment": "低优先级"},
      {"name": "MEDIUM", "value": 1, "comment": "中优先级"},
      {"name": "HIGH", "value": 2, "comment": "高优先级"}
    ]
  }')

if [[ "$response" == "Enum created successfully" ]]; then
    print_success "带注释的枚举创建成功"
else
    print_failure "带注释的枚举创建失败" "$response"
fi

# 测试 3: 1字节枚举
print_test "测试 3: 创建 1字节枚举 (Status)"
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Status",
    "categoryPath": "/",
    "size": 1,
    "description": "状态码",
    "values": [
      {"name": "OK", "value": 0},
      {"name": "ERROR", "value": 1},
      {"name": "PENDING", "value": 2}
    ]
  }')

if [[ "$response" == "Enum created successfully" ]]; then
    print_success "1字节枚举创建成功"
else
    print_failure "1字节枚举创建失败" "$response"
fi

# 测试 4: 2字节枚举
print_test "测试 4: 创建 2字节枚举 (ErrorCode)"
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ErrorCode",
    "categoryPath": "/System",
    "size": 2,
    "values": [
      {"name": "SUCCESS", "value": 0},
      {"name": "INVALID_PARAM", "value": 100},
      {"name": "OUT_OF_MEMORY", "value": 200}
    ]
  }')

if [[ "$response" == "Enum created successfully" ]]; then
    print_success "2字节枚举创建成功"
else
    print_failure "2字节枚举创建失败" "$response"
fi

# 测试 5: 8字节枚举
print_test "测试 5: 创建 8字节枚举 (LargeValue)"
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "LargeValue",
    "categoryPath": "/Test",
    "size": 8,
    "values": [
      {"name": "MIN", "value": 0},
      {"name": "MAX", "value": 9223372036854775807}
    ]
  }')

if [[ "$response" == "Enum created successfully" ]]; then
    print_success "8字节枚举创建成功"
else
    print_failure "8字节枚举创建失败" "$response"
fi

# 测试 6: 错误处理 - 无效的 size
print_test "测试 6: 错误处理 - 无效的 size (size=3)"
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "InvalidSize",
    "categoryPath": "/",
    "size": 3,
    "values": [
      {"name": "VALUE", "value": 0}
    ]
  }')

if [[ "$response" == *"Error"* ]] && [[ "$response" == *"size must be 1, 2, 4, or 8"* ]]; then
    print_success "正确拒绝了无效的 size 值"
else
    print_failure "未能正确处理无效的 size 值" "$response"
fi

# 测试 7: 错误处理 - 缺少必需字段
print_test "测试 7: 错误处理 - 缺少必需字段 (缺少 name)"
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "categoryPath": "/",
    "size": 4,
    "values": [
      {"name": "VALUE", "value": 0}
    ]
  }')

if [[ "$response" == *"Error"* ]] && [[ "$response" == *"name"* ]]; then
    print_success "正确检测到缺少的 name 字段"
else
    print_failure "未能正确检测缺少的 name 字段" "$response"
fi

# 测试 8: 错误处理 - 空的 values 数组
print_test "测试 8: 错误处理 - 空的 values 数组"
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "EmptyEnum",
    "categoryPath": "/",
    "size": 4,
    "values": []
  }')

if [[ "$response" == *"Error"* ]] && [[ "$response" == *"at least one"* ]]; then
    print_success "正确拒绝了空的 values 数组"
else
    print_failure "未能正确处理空的 values 数组" "$response"
fi

# 测试 9: 错误处理 - 枚举值名称重复
print_test "测试 9: 错误处理 - 枚举值名称重复"
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DuplicateTest",
    "categoryPath": "/",
    "size": 4,
    "values": [
      {"name": "VALUE", "value": 0},
      {"name": "VALUE", "value": 1}
    ]
  }')

if [[ "$response" == *"Error"* ]] && [[ "$response" == *"Duplicate"* ]]; then
    print_success "正确检测到重复的枚举值名称"
else
    print_failure "未能正确检测重复的枚举值名称" "$response"
fi

# 测试 10: 错误处理 - 名称冲突 (重复创建同一枚举)
print_test "测试 10: 错误处理 - 名称冲突"
# 首先创建一个枚举
curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ConflictTest",
    "categoryPath": "/",
    "size": 4,
    "values": [
      {"name": "VALUE", "value": 0}
    ]
  }' > /dev/null

# 再次尝试创建相同的枚举
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ConflictTest",
    "categoryPath": "/",
    "size": 4,
    "values": [
      {"name": "VALUE", "value": 0}
    ]
  }')

if [[ "$response" == *"Error"* ]] && [[ "$response" == *"already exists"* ]]; then
    print_success "正确检测到名称冲突"
else
    print_failure "未能正确检测名称冲突" "$response"
fi

# 测试 11: 复杂的现实世界枚举
print_test "测试 11: 创建复杂的现实世界枚举 (Windows MessageType)"
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "WindowsMessageType",
    "categoryPath": "/Windows",
    "size": 4,
    "description": "Windows 消息类型",
    "values": [
      {"name": "WM_NULL", "value": 0, "comment": "空消息"},
      {"name": "WM_CREATE", "value": 1, "comment": "创建窗口"},
      {"name": "WM_DESTROY", "value": 2, "comment": "销毁窗口"},
      {"name": "WM_MOVE", "value": 3, "comment": "移动窗口"},
      {"name": "WM_SIZE", "value": 5, "comment": "改变窗口大小"}
    ]
  }')

if [[ "$response" == "Enum created successfully" ]]; then
    print_success "复杂枚举创建成功"
else
    print_failure "复杂枚举创建失败" "$response"
fi

# 测试 12: 枚举值可以对应相同的值
print_test "测试 12: 枚举值可以对应相同的值"
response=$(curl -s -X POST "${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AliasTest",
    "categoryPath": "/",
    "size": 4,
    "values": [
      {"name": "VALUE_1", "value": 0},
      {"name": "VALUE_2", "value": 0},
      {"name": "VALUE_3", "value": 1}
    ]
  }')

if [[ "$response" == "Enum created successfully" ]]; then
    print_success "允许不同的枚举名对应相同的值"
else
    print_failure "不允许不同的枚举名对应相同的值" "$response"
fi

# 测试总结
echo -e "\n${YELLOW}========================================${NC}"
echo -e "${YELLOW}测试总结${NC}"
echo -e "${YELLOW}========================================${NC}"
echo -e "${GREEN}通过的测试: ${TESTS_PASSED}${NC}"
echo -e "${RED}失败的测试: ${TESTS_FAILED}${NC}"
echo -e "总计测试: $((TESTS_PASSED + TESTS_FAILED))"

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "\n${GREEN}所有测试通过!${NC}"
    exit 0
else
    echo -e "\n${RED}有测试失败,请检查实现${NC}"
    exit 1
fi
