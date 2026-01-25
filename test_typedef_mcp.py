#!/usr/bin/env python3
"""
测试 Typedef 创建功能的 Python 脚本
通过直接调用 HTTP 端点来测试 POST /data_types/typedef
"""

import requests
import json
import time

GHIDRA_SERVER = "http://127.0.0.1:8080"

def print_test(test_name):
    """打印测试标题"""
    print(f"\n{'='*60}")
    print(f"{test_name}")
    print('='*60)

def test_simple_typedef():
    """测试 1: 创建简单的 Typedef"""
    print_test("测试 1: 创建简单的 Typedef (int 类型的别名)")

    url = f"{GHIDRA_SERVER}/data_types/typedef"
    data = {
        "name": "MyIntPtr",
        "categoryPath": "/MyTypes",
        "baseDataType": "/int"
    }

    print(f"POST {url}")
    print(f"Data: {json.dumps(data, indent=2)}")

    response = requests.post(url, json=data, headers={"Content-Type": "application/json"})
    print(f"\n响应 (HTTP {response.status_code}):")
    print(response.text)

    time.sleep(1)

def test_pointer_typedef():
    """测试 2: 创建指针 Typedef"""
    print_test("测试 2: 创建指针 Typedef (PersonPtr)")

    # 步骤 1: 创建 Person 结构体
    print("步骤 1: 创建 Person 结构体")
    url = f"{GHIDRA_SERVER}/data_types/struct"
    data = {
        "name": "Person",
        "categoryPath": "/MyTypes",
        "description": "人员信息结构体",
        "fields": [
            {"name": "id", "dataType": "/int", "length": 4, "comment": "人员ID"},
            {"name": "name", "dataType": "/char", "length": 32, "comment": "姓名"}
        ]
    }

    print(f"POST {url}")
    response = requests.post(url, json=data, headers={"Content-Type": "application/json"})
    print(f"响应: {response.text}")

    time.sleep(1)

    # 步骤 2: 创建指向 Person 的指针 Typedef
    print("\n步骤 2: 创建 PersonPtr 指针 Typedef")
    url = f"{GHIDRA_SERVER}/data_types/typedef"
    data = {
        "name": "PersonPtr",
        "categoryPath": "/MyTypes",
        "baseDataType": "/MyTypes/Person",
        "isPointer": True
    }

    print(f"POST {url}")
    print(f"Data: {json.dumps(data, indent=2)}")
    response = requests.post(url, json=data, headers={"Content-Type": "application/json"})
    print(f"\n响应 (HTTP {response.status_code}):")
    print(response.text)

    time.sleep(1)

def test_verify_typedef():
    """测试 3: 验证 Typedef 已创建"""
    print_test("测试 3: 验证 Typedef 已创建")

    print("搜索 MyIntPtr:")
    url = f"{GHIDRA_SERVER}/data_types/search"
    params = {"name": "MyIntPtr", "limit": 5}
    response = requests.get(url, params=params)
    print(response.text)

    print("\n搜索 PersonPtr:")
    params = {"name": "PersonPtr", "limit": 5}
    response = requests.get(url, params=params)
    print(response.text)

    time.sleep(1)

def test_get_typedef_details():
    """测试 4: 获取 Typedef 详细信息"""
    print_test("测试 4: 获取 Typedef 详细信息")

    print("获取 MyIntPtr 详情:")
    url = f"{GHIDRA_SERVER}/data_types/MyTypes/MyIntPtr"
    response = requests.get(url)
    print(f"响应 (HTTP {response.status_code}):")
    print(response.text)

    time.sleep(1)

def test_void_pointer_typedef():
    """测试 5: 创建指向内置类型的指针 Typedef"""
    print_test("测试 5: 创建指向内置类型的指针 Typedef (VoidPtr)")

    url = f"{GHIDRA_SERVER}/data_types/typedef"
    data = {
        "name": "VoidPtr",
        "categoryPath": "/MyTypes",
        "baseDataType": "/void",
        "isPointer": True
    }

    print(f"POST {url}")
    print(f"Data: {json.dumps(data, indent=2)}")
    response = requests.post(url, json=data, headers={"Content-Type": "application/json"})
    print(f"\n响应 (HTTP {response.status_code}):")
    print(response.text)

    time.sleep(1)

def test_invalid_base_type():
    """测试 6: 错误处理 - 基础类型不存在"""
    print_test("测试 6: 错误处理 - 基础类型不存在")

    url = f"{GHIDRA_SERVER}/data_types/typedef"
    data = {
        "name": "InvalidTypedef",
        "categoryPath": "/MyTypes",
        "baseDataType": "/NonExistentType"
    }

    print(f"POST {url}")
    print(f"Data: {json.dumps(data, indent=2)}")
    response = requests.post(url, json=data, headers={"Content-Type": "application/json"})
    print(f"\n响应 (HTTP {response.status_code}):")
    print(response.text)

    time.sleep(1)

def test_duplicate_name():
    """测试 7: 错误处理 - 名称冲突"""
    print_test("测试 7: 错误处理 - 名称冲突 (重复创建 MyIntPtr)")

    url = f"{GHIDRA_SERVER}/data_types/typedef"
    data = {
        "name": "MyIntPtr",
        "categoryPath": "/MyTypes",
        "baseDataType": "/int"
    }

    print(f"POST {url}")
    print(f"Data: {json.dumps(data, indent=2)}")
    response = requests.post(url, json=data, headers={"Content-Type": "application/json"})
    print(f"\n响应 (HTTP {response.status_code}):")
    print(response.text)

    time.sleep(1)

def test_missing_fields():
    """测试 8: 错误处理 - 缺少必需字段"""
    print_test("测试 8: 错误处理 - 缺少必需字段")

    url = f"{GHIDRA_SERVER}/data_types/typedef"
    data = {
        "name": "TestTypedef"
    }

    print(f"POST {url}")
    print(f"Data: {json.dumps(data, indent=2)}")
    response = requests.post(url, json=data, headers={"Content-Type": "application/json"})
    print(f"\n响应 (HTTP {response.status_code}):")
    print(response.text)

    time.sleep(1)

def test_enum_typedef():
    """测试 9: Typedef 指向枚举类型"""
    print_test("测试 9: Typedef 指向枚举类型")

    # 步骤 1: 创建一个枚举
    print("步骤 1: 创建枚举 Status")
    url = f"{GHIDRA_SERVER}/data_types/enum"
    data = {
        "name": "Status",
        "categoryPath": "/MyTypes",
        "size": 4,
        "description": "状态枚举",
        "values": [
            {"name": "OK", "value": 0, "comment": "成功"},
            {"name": "ERROR", "value": 1, "comment": "错误"},
            {"name": "PENDING", "value": 2, "comment": "等待中"}
        ]
    }

    print(f"POST {url}")
    response = requests.post(url, json=data, headers={"Content-Type": "application/json"})
    print(f"响应: {response.text}")

    time.sleep(1)

    # 步骤 2: 创建指向枚举的 Typedef
    print("\n步骤 2: 创建 StatusCode Typedef")
    url = f"{GHIDRA_SERVER}/data_types/typedef"
    data = {
        "name": "StatusCode",
        "categoryPath": "/MyTypes",
        "baseDataType": "/MyTypes/Status"
    }

    print(f"POST {url}")
    print(f"Data: {json.dumps(data, indent=2)}")
    response = requests.post(url, json=data, headers={"Content-Type": "application/json"})
    print(f"\n响应 (HTTP {response.status_code}):")
    print(response.text)

    time.sleep(1)

def test_list_types():
    """测试 10: 列出 /MyTypes 类别下的所有类型"""
    print_test("测试 10: 列出所有数据类型")

    url = f"{GHIDRA_SERVER}/data_types"
    params = {"limit": 20}
    response = requests.get(url, params=params)

    print("所有数据类型 (前20个):")
    lines = response.text.split('\n')
    mytypes = [line for line in lines if '/mytypes' in line.lower()]
    for line in mytypes:
        print(f"  {line}")

def main():
    """运行所有测试"""
    print("=========================================")
    print("Typedef 创建功能测试")
    print("=========================================")

    try:
        # 运行所有测试
        test_simple_typedef()
        test_pointer_typedef()
        test_verify_typedef()
        test_get_typedef_details()
        test_void_pointer_typedef()
        test_invalid_base_type()
        test_duplicate_name()
        test_missing_fields()
        test_enum_typedef()
        test_list_types()

        print("\n=========================================")
        print("所有测试完成!")
        print("=========================================")

    except requests.exceptions.ConnectionError:
        print("\n错误: 无法连接到 Ghidra HTTP 服务器")
        print(f"请确保 Ghidra 正在运行,并且 MCP 插件已启动在 {GHIDRA_SERVER}")
    except Exception as e:
        print(f"\n错误: {e}")

if __name__ == "__main__":
    main()
