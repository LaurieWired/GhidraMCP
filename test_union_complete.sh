#!/bin/bash

# 联合体 (Union) 完整测试脚本
# 测试 Task 2.3: 创建联合体,包括所有复杂的嵌套场景

set -e

GHIDRA_SERVER="${GHIDRA_SERVER:-http://127.0.0.1:8080}"

echo "========================================"
echo "联合体 (Union) 完整测试脚本"
echo "Ghidra 服务器: $GHIDRA_SERVER"
echo "========================================"
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试计数器
TESTS_PASSED=0
TESTS_FAILED=0

# 测试函数
test_request() {
    local test_name="$1"
    local endpoint="$2"
    local data="$3"
    local expected_success="$4"

    echo -e "${YELLOW}测试:${NC} $test_name"
    echo "端点: $endpoint"

    response=$(curl -s -X POST \
        "$GHIDRA_SERVER$endpoint" \
        -H "Content-Type: application/json" \
        -d "$data")

    if [ "$expected_success" = "true" ]; then
        if echo "$response" | grep -q "successfully"; then
            echo -e "${GREEN}✓ 通过${NC}"
            echo "响应: $response"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "${RED}✗ 失败${NC}"
            echo "响应: $response"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        if echo "$response" | grep -q "Error"; then
            echo -e "${GREEN}✓ 通过 (预期失败)${NC}"
            echo "响应: $response"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "${RED}✗ 失败 (应该返回错误)${NC}"
            echo "响应: $response"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
    echo ""
}

echo "========================================"
echo "阶段 1: 准备工作 - 创建依赖类型"
echo "========================================"
echo ""

# 1.1 创建简单的结构体 (Person)
echo "1.1 创建 Person 结构体..."
test_request "创建 Person 结构体" \
    "data_types/struct" \
    '{
        "name": "Person",
        "categoryPath": "/MyTypes",
        "description": "人员信息结构体",
        "fields": [
            {"name": "id", "dataType": "/int", "length": 4, "comment": "人员ID"},
            {"name": "name", "dataType": "/char", "length": 32, "comment": "姓名"},
            {"name": "age", "dataType": "/int", "length": 4, "comment": "年龄"}
        ]
    }' \
    "true"

# 1.2 创建 Address 结构体
echo "1.2 创建 Address 结构体..."
test_request "创建 Address 结构体" \
    "data_types/struct" \
    '{
        "name": "Address",
        "categoryPath": "/MyTypes",
        "description": "地址信息结构体",
        "fields": [
            {"name": "street", "dataType": "/char", "length": 64, "comment": "街道"},
            {"name": "city", "dataType": "/char", "length": 32, "comment": "城市"},
            {"name": "zipCode", "dataType": "/int", "length": 4, "comment": "邮编"}
        ]
    }' \
    "true"

# 1.3 创建 Color 枚举
echo "1.3 创建 Color 枚举..."
test_request "创建 Color 枚举" \
    "data_types/enum" \
    '{
        "name": "Color",
        "categoryPath": "/MyTypes",
        "size": 4,
        "description": "颜色枚举",
        "values": [
            {"name": "RED", "value": 0, "comment": "红色"},
            {"name": "GREEN", "value": 1, "comment": "绿色"},
            {"name": "BLUE", "value": 2, "comment": "蓝色"}
        ]
    }' \
    "true"

# 1.4 创建 Priority 枚举
echo "1.4 创建 Priority 枚举..."
test_request "创建 Priority 枚举" \
    "data_types/enum" \
    '{
        "name": "Priority",
        "categoryPath": "/MyTypes",
        "size": 4,
        "values": [
            {"name": "LOW", "value": 0},
            {"name": "MEDIUM", "value": 1},
            {"name": "HIGH", "value": 2}
        ]
    }' \
    "true"

# 1.5 创建 PersonPtr Typedef
echo "1.5 创建 PersonPtr Typedef..."
test_request "创建 PersonPtr Typedef" \
    "data_types/typedef" \
    '{
        "name": "PersonPtr",
        "categoryPath": "/MyTypes",
        "baseDataType": "/MyTypes/Person",
        "isPointer": true
    }' \
    "true"

# 1.6 创建 AddressPtr Typedef
echo "1.6 创建 AddressPtr Typedef..."
test_request "创建 AddressPtr Typedef" \
    "data_types/typedef" \
    '{
        "name": "AddressPtr",
        "categoryPath": "/MyTypes",
        "baseDataType": "/MyTypes/Address",
        "isPointer": true
    }' \
    "true"

echo "========================================"
echo "阶段 2: 基础联合体测试"
echo "========================================"
echo ""

# 2.1 创建最简单的联合体 (int + float)
echo "2.1 创建 IntFloat 联合体..."
test_request "创建 IntFloat 联合体 (int + float)" \
    "data_types/union" \
    '{
        "name": "IntFloat",
        "categoryPath": "/Primitives",
        "description": "整数和浮点数联合体",
        "fields": [
            {"name": "asInt", "dataType": "/int", "length": 4, "comment": "作为整数"},
            {"name": "asFloat", "dataType": "/float", "length": 4, "comment": "作为浮点数"}
        ]
    }' \
    "true"

# 2.2 创建多基本类型的联合体
echo "2.2 创建 MultiType 联合体..."
test_request "创建 MultiType 联合体 (多种基本类型)" \
    "data_types/union" \
    '{
        "name": "MultiType",
        "categoryPath": "/Primitives",
        "fields": [
            {"name": "asInt", "dataType": "/int", "length": 4},
            {"name": "asUInt", "dataType": "/uint", "length": 4},
            {"name": "asFloat", "dataType": "/float", "length": 4},
            {"name": "asDouble", "dataType": "/double", "length": 8},
            {"name": "asByte", "dataType": "/char", "length": 1}
        ]
    }' \
    "true"

# 2.3 创建带字节数组的联合体
echo "2.3 创建 RawData 联合体..."
test_request "创建 RawData 联合体 (int + byte array)" \
    "data_types/union" \
    '{
        "name": "RawData",
        "categoryPath": "/Primitives",
        "description": "原始数据联合体",
        "fields": [
            {"name": "asInt", "dataType": "/int", "length": 4, "comment": "作为整数"},
            {"name": "asBytes", "dataType": "/uchar", "length": 4, "comment": "作为4字节数组"}
        ]
    }' \
    "true"

echo "========================================"
echo "阶段 3: 嵌套结构体的联合体 ⭐"
echo "========================================"
echo ""

# 3.1 联合体包含结构体 (Person)
echo "3.1 创建 Variant1 联合体..."
test_request "创建包含 Person 结构体的联合体" \
    "data_types/union" \
    '{
        "name": "Variant1",
        "categoryPath": "/MyTypes",
        "description": "包含 Person 结构体的联合体",
        "fields": [
            {"name": "asPerson", "dataType": "/MyTypes/Person", "length": 40, "comment": "作为 Person 结构体"},
            {"name": "asInt", "dataType": "/int", "length": 4, "comment": "作为整数"}
        ]
    }' \
    "true"

# 3.2 联合体包含多个结构体
echo "3.2 创建 Variant2 联合体..."
test_request "创建包含 Person 和 Address 结构体的联合体" \
    "data_types/union" \
    '{
        "name": "Variant2",
        "categoryPath": "/MyTypes",
        "description": "包含多个结构体的联合体",
        "fields": [
            {"name": "asPerson", "dataType": "/MyTypes/Person", "length": 40, "comment": "作为 Person"},
            {"name": "asAddress", "dataType": "/MyTypes/Address", "length": 100, "comment": "作为 Address"}
        ]
    }' \
    "true"

echo "========================================"
echo "阶段 4: 嵌套枚举的联合体 ⭐"
echo "========================================"
echo ""

# 4.1 联合体包含枚举 (Color)
echo "4.1 创建 ColorValue 联合体..."
test_request "创建包含 Color 枚举的联合体" \
    "data_types/union" \
    '{
        "name": "ColorValue",
        "categoryPath": "/MyTypes",
        "description": "包含 Color 枚举的联合体",
        "fields": [
            {"name": "asColor", "dataType": "/MyTypes/Color", "length": 4, "comment": "作为 Color 枚举"},
            {"name": "asInt", "dataType": "/int", "length": 4, "comment": "作为整数"}
        ]
    }' \
    "true"

# 4.2 联合体包含多个枚举
echo "4.2 创建 StatusUnion 联合体..."
test_request "创建包含多个枚举的联合体" \
    "data_types/union" \
    '{
        "name": "StatusUnion",
        "categoryPath": "/MyTypes",
        "fields": [
            {"name": "asColor", "dataType": "/MyTypes/Color", "length": 4},
            {"name": "asPriority", "dataType": "/MyTypes/Priority", "length": 4}
        ]
    }' \
    "true"

echo "========================================"
echo "阶段 5: 嵌套 Typedef 的联合体 ⭐"
echo "========================================"
echo ""

# 5.1 联合体包含指针 Typedef
echo "5.1 创建 PointerUnion 联合体..."
test_request "创建包含 PersonPtr Typedef 的联合体" \
    "data_types/union" \
    '{
        "name": "PointerUnion",
        "categoryPath": "/MyTypes",
        "description": "包含指针 Typedef 的联合体",
        "fields": [
            {"name": "asPersonPtr", "dataType": "/MyTypes/PersonPtr", "length": 4, "comment": "作为 Person 指针"},
            {"name": "asAddressPtr", "dataType": "/MyTypes/AddressPtr", "length": 4, "comment": "作为 Address 指针"}
        ]
    }' \
    "true"

echo "========================================"
echo "阶段 6: 终极复杂联合体 ⭐⭐⭐"
echo "========================================"
echo ""

# 6.1 联合体包含所有类型 (结构体 + 枚举 + Typedef + 基本类型)
echo "6.1 创建 UltimateVariant 联合体..."
test_request "创建终极联合体 (包含所有类型)" \
    "data_types/union" \
    '{
        "name": "UltimateVariant",
        "categoryPath": "/MyTypes",
        "description": "终极联合体 - 包含所有类型的嵌套",
        "fields": [
            {"name": "asPerson", "dataType": "/MyTypes/Person", "length": 40, "comment": "作为 Person 结构体"},
            {"name": "asAddress", "dataType": "/MyTypes/Address", "length": 100, "comment": "作为 Address 结构体"},
            {"name": "asColor", "dataType": "/MyTypes/Color", "length": 4, "comment": "作为 Color 枚举"},
            {"name": "asPriority", "dataType": "/MyTypes/Priority", "length": 4, "comment": "作为 Priority 枚举"},
            {"name": "asPersonPtr", "dataType": "/MyTypes/PersonPtr", "length": 4, "comment": "作为 Person 指针 Typedef"},
            {"name": "asAddressPtr", "dataType": "/MyTypes/AddressPtr", "length": 4, "comment": "作为 Address 指针 Typedef"},
            {"name": "asInt", "dataType": "/int", "length": 4, "comment": "作为整数"},
            {"name": "asFloat", "dataType": "/float", "length": 4, "comment": "作为浮点数"},
            {"name": "asBytes", "dataType": "/uchar", "length": 100, "comment": "作为100字节数组"}
        ]
    }' \
    "true"

echo "========================================"
echo "阶段 7: 错误处理测试"
echo "========================================"
echo ""

# 7.1 测试重复名称
echo "7.1 测试重复名称的联合体..."
test_request "创建重复名称的联合体 (应该失败)" \
    "data_types/union" \
    '{
        "name": "IntFloat",
        "categoryPath": "/Primitives",
        "fields": [
            {"name": "asInt", "dataType": "/int", "length": 4}
        ]
    }' \
    "false"

# 7.2 测试不存在的类型
echo "7.2 测试不存在的类型..."
test_request "使用不存在的类型 (应该失败)" \
    "data_types/union" \
    '{
        "name": "BadUnion",
        "categoryPath": "/MyTypes",
        "fields": [
            {"name": "asBadType", "dataType": "/NonExistent/Type", "length": 4}
        ]
    }' \
    "false"

# 7.3 测试缺少必需字段
echo "7.3 测试缺少必需字段..."
test_request "缺少 name 字段 (应该失败)" \
    "data_types/union" \
    '{
        "categoryPath": "/MyTypes",
        "fields": [
            {"name": "asInt", "dataType": "/int", "length": 4}
        ]
    }' \
    "false"

# 7.4 测试空字段列表
echo "7.4 测试空字段列表..."
test_request "空字段列表 (应该失败)" \
    "data_types/union" \
    '{
        "name": "EmptyUnion",
        "categoryPath": "/MyTypes",
        "fields": []
    }' \
    "false"

echo "========================================"
echo "阶段 8: 验证创建的类型"
echo "========================================"
echo ""

# 8.1 验证 UltimateVariant 联合体
echo "8.1 获取 UltimateVariant 联合体详情..."
response=$(curl -s "$GHIDRA_SERVER/data_types/MyTypes/UltimateVariant")
echo "响应: $response"
if echo "$response" | grep -q "UltimateVariant"; then
    echo -e "${GREEN}✓ 联合体验证成功${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ 联合体验证失败${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# 8.2 列出所有数据类型,验证所有创建的类型
echo "8.2 列出 /MyTypes 下的所有数据类型..."
response=$(curl -s "$GHIDRA_SERVER/data_types?offset=0&limit=100" | grep -c "/MyTypes/" || true)
echo "找到 $response 个 /MyTypes/ 下的类型"

# 检查关键类型是否存在
echo "检查关键类型..."
for type in "Person" "Address" "Color" "Priority" "PersonPtr" "AddressPtr" "Variant1" "Variant2" "ColorValue" "PointerUnion" "UltimateVariant"; do
    if curl -s "$GHIDRA_SERVER/data_types?offset=0&limit=200" | grep -q "/MyTypes/$type"; then
        echo -e "${GREEN}✓ 找到: $type${NC}"
    else
        echo -e "${RED}✗ 未找到: $type${NC}"
    fi
done

echo ""
echo "========================================"
echo "测试总结"
echo "========================================"
echo -e "${GREEN}通过: $TESTS_PASSED${NC}"
echo -e "${RED}失败: $TESTS_FAILED${NC}"
echo "总计: $((TESTS_PASSED + TESTS_FAILED))"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 所有测试通过!${NC}"
    exit 0
else
    echo -e "${RED}❌ 有测试失败${NC}"
    exit 1
fi
