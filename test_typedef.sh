#!/bin/bash

# 测试 Typedef 创建功能的脚本
# 这个脚本测试 POST /data_types/typedef 端点

GHIDRA_SERVER="http://127.0.0.1:8080"

echo "========================================="
echo "测试 Typedef 创建功能"
echo "========================================="
echo ""

# 测试 1: 创建简单的 Typedef (int 类型的别名)
echo "测试 1: 创建简单的 Typedef (int 类型的别名)"
echo "-------------------------------------------"
curl -X POST ${GHIDRA_SERVER}/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MyIntPtr",
    "categoryPath": "/MyTypes",
    "baseDataType": "/int"
  }'
echo -e "\n"

# 等待一下
sleep 1

# 测试 2: 创建指针 Typedef
echo "测试 2: 创建指针 Typedef (PersonPtr)"
echo "-------------------------------------------"
# 首先创建一个 Person 结构体
echo "步骤 1: 创建 Person 结构体"
curl -X POST ${GHIDRA_SERVER}/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Person",
    "categoryPath": "/MyTypes",
    "description": "人员信息结构体",
    "fields": [
      {"name": "id", "dataType": "/int", "length": 4, "comment": "人员ID"},
      {"name": "name", "dataType": "/char", "length": 32, "comment": "姓名"}
    ]
  }'
echo -e "\n"

sleep 1

# 然后创建指向 Person 的指针 Typedef
echo "步骤 2: 创建 PersonPtr 指针 Typedef"
curl -X POST ${GHIDRA_SERVER}/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PersonPtr",
    "categoryPath": "/MyTypes",
    "baseDataType": "/MyTypes/Person",
    "isPointer": true
  }'
echo -e "\n"

sleep 1

# 测试 3: 验证 Typedef 已创建
echo "测试 3: 验证 Typedef 已创建"
echo "-------------------------------------------"
echo "搜索 MyIntPtr:"
curl -s "${GHIDRA_SERVER}/data_types/search?name=MyIntPtr&limit=5"
echo -e "\n"

echo "搜索 PersonPtr:"
curl -s "${GHIDRA_SERVER}/data_types/search?name=PersonPtr&limit=5"
echo -e "\n"

sleep 1

# 测试 4: 获取 Typedef 详细信息
echo "测试 4: 获取 Typedef 详细信息"
echo "-------------------------------------------"
echo "获取 MyIntPtr 详情:"
curl -s "${GHIDRA_SERVER}/data_types/MyTypes/MyIntPtr"
echo -e "\n"

sleep 1

# 测试 5: 创建指向内置类型的指针 Typedef
echo "测试 5: 创建指向内置类型的指针 Typedef"
echo "-------------------------------------------"
curl -X POST ${GHIDRA_SERVER}/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "VoidPtr",
    "categoryPath": "/MyTypes",
    "baseDataType": "/void",
    "isPointer": true
  }'
echo -e "\n"

sleep 1

# 测试 6: 错误处理 - 基础类型不存在
echo "测试 6: 错误处理 - 基础类型不存在"
echo "-------------------------------------------"
curl -X POST ${GHIDRA_SERVER}/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "InvalidTypedef",
    "categoryPath": "/MyTypes",
    "baseDataType": "/NonExistentType"
  }'
echo -e "\n"

sleep 1

# 测试 7: 错误处理 - 名称冲突
echo "测试 7: 错误处理 - 名称冲突 (重复创建 MyIntPtr)"
echo "-------------------------------------------"
curl -X POST ${GHIDRA_SERVER}/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MyIntPtr",
    "categoryPath": "/MyTypes",
    "baseDataType": "/int"
  }'
echo -e "\n"

sleep 1

# 测试 8: 错误处理 - 缺少必需字段
echo "测试 8: 错误处理 - 缺少必需字段"
echo "-------------------------------------------"
curl -X POST ${GHIDRA_SERVER}/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TestTypedef"
  }'
echo -e "\n"

# 测试 9: Typedef 指向枚举类型
echo "测试 9: Typedef 指向枚举类型"
echo "-------------------------------------------"
# 首先创建一个枚举
echo "步骤 1: 创建枚举 Status"
curl -X POST ${GHIDRA_SERVER}/data_types/enum \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Status",
    "categoryPath": "/MyTypes",
    "size": 4,
    "description": "状态枚举",
    "values": [
      {"name": "OK", "value": 0, "comment": "成功"},
      {"name": "ERROR", "value": 1, "comment": "错误"},
      {"name": "PENDING", "value": 2, "comment": "等待中"}
    ]
  }'
echo -e "\n"

sleep 1

# 然后创建指向枚举的 Typedef
echo "步骤 2: 创建 StatusCode Typedef"
curl -X POST ${GHIDRA_SERVER}/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "StatusCode",
    "categoryPath": "/MyTypes",
    "baseDataType": "/MyTypes/Status"
  }'
echo -e "\n"

sleep 1

# 测试 10: 列出 /MyTypes 类别下的所有类型
echo "测试 10: 列出 /MyTypes 类别下的所有类型"
echo "-------------------------------------------"
curl -s "${GHIDRA_SERVER}/data_types?limit=20" | grep -i "/mytypes" || echo "完成"
echo -e "\n"

echo "========================================="
echo "测试完成!"
echo "========================================="
