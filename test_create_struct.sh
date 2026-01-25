#!/bin/bash

# 测试创建结构体功能
# 此脚本测试 POST /data_types/struct 端点

GHIDRA_SERVER="http://127.0.0.1:8080"

echo "========================================"
echo "测试 1: 创建简单的 Point 结构体"
echo "========================================"
curl -X POST "${GHIDRA_SERVER}/data_types/struct" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Point",
    "categoryPath": "/Geometry",
    "description": "二维点坐标",
    "fields": [
      {"name": "x", "dataType": "/int", "length": 4, "comment": "X坐标"},
      {"name": "y", "dataType": "/int", "length": 4, "comment": "Y坐标"}
    ]
  }'
echo -e "\n"

echo "========================================"
echo "测试 2: 创建 Address 结构体"
echo "========================================"
curl -X POST "${GHIDRA_SERVER}/data_types/struct" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Address",
    "categoryPath": "/MyTypes",
    "description": "地址信息",
    "fields": [
      {"name": "street", "dataType": "/char", "length": 32, "comment": "街道名称"},
      {"name": "city", "dataType": "/char", "length": 32, "comment": "城市"},
      {"name": "zip", "dataType": "/int", "length": 4, "comment": "邮编"}
    ]
  }'
echo -e "\n"

echo "========================================"
echo "测试 3: 创建嵌套结构体 Person (包含 Address 字段)"
echo "========================================"
curl -X POST "${GHIDRA_SERVER}/data_types/struct" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Person",
    "categoryPath": "/MyTypes",
    "description": "人员信息结构体",
    "fields": [
      {"name": "id", "dataType": "/int", "length": 4, "comment": "人员ID"},
      {"name": "name", "dataType": "/char", "length": 32, "comment": "姓名"},
      {"name": "age", "dataType": "/int", "length": 4, "comment": "年龄"},
      {"name": "address", "dataType": "/MyTypes/Address", "length": 68, "comment": "地址"}
    ]
  }'
echo -e "\n"

echo "========================================"
echo "测试 4: 创建复杂结构体 Employee"
echo "========================================"
curl -X POST "${GHIDRA_SERVER}/data_types/struct" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Employee",
    "categoryPath": "/Company",
    "description": "员工信息",
    "fields": [
      {"name": "employeeId", "dataType": "/int", "length": 4, "comment": "员工ID"},
      {"name": "name", "dataType": "/char", "length": 64, "comment": "员工姓名"},
      {"name": "department", "dataType": "/char", "length": 32, "comment": "部门"},
      {"name": "salary", "dataType": "/longlong", "length": 8, "comment": "薪资"},
      {"name": "isActive", "dataType": "/bool", "length": 1, "comment": "是否在职"}
    ]
  }'
echo -e "\n"

echo "========================================"
echo "测试 5: 错误处理 - 创建重复的结构体"
echo "========================================"
curl -X POST "${GHIDRA_SERVER}/data_types/struct" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Point",
    "categoryPath": "/Geometry",
    "fields": [
      {"name": "x", "dataType": "/int", "length": 4}
    ]
  }'
echo -e "\n"

echo "========================================"
echo "测试 6: 错误处理 - 缺少必需字段"
echo "========================================"
curl -X POST "${GHIDRA_SERVER}/data_types/struct" \
  -H "Content-Type: application/json" \
  -d '{
    "categoryPath": "/Test",
    "fields": [
      {"name": "test", "dataType": "/int", "length": 4}
    ]
  }'
echo -e "\n"

echo "========================================"
echo "测试 7: 错误处理 - 字段类型不存在"
echo "========================================"
curl -X POST "${GHIDRA_SERVER}/data_types/struct" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TestStruct",
    "categoryPath": "/Test",
    "fields": [
      {"name": "field1", "dataType": "/NonExistentType", "length": 4}
    ]
  }'
echo -e "\n"

echo "========================================"
echo "测试 8: 验证结构体已创建"
echo "========================================"
echo "查询所有数据类型:"
curl -s "${GHIDRA_SERVER}/data_types?limit=100" | grep -E "(Point|Address|Person|Employee)"
echo -e "\n"

echo "========================================"
echo "测试完成！"
echo "========================================"
