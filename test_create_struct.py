#!/usr/bin/env python3
"""
测试创建结构体功能

此脚本测试 POST /data_types/struct 端点，包括：
1. 简单结构体
2. 嵌套结构体
3. 错误处理
"""

import requests
import json
import sys

GHIDRA_SERVER = "http://127.0.0.1:8080"

def print_section(title):
    """打印测试部分标题"""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)

def create_struct(name, category_path, fields, description=""):
    """创建结构体"""
    url = f"{GHIDRA_SERVER}/data_types/struct"
    data = {
        "name": name,
        "categoryPath": category_path,
        "fields": fields
    }
    if description:
        data["description"] = description

    try:
        response = requests.post(
            url,
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return response.status_code, response.text.strip()
    except Exception as e:
        return -1, f"Request failed: {str(e)}"

def test_simple_struct():
    """测试 1: 创建简单的 Point 结构体"""
    print_section("测试 1: 创建简单的 Point 结构体")

    status, result = create_struct(
        name="Point",
        category_path="/Geometry",
        description="二维点坐标",
        fields=[
            {"name": "x", "dataType": "/int", "length": 4, "comment": "X坐标"},
            {"name": "y", "dataType": "/int", "length": 4, "comment": "Y坐标"}
        ]
    )

    print(f"状态码: {status}")
    print(f"结果: {result}")
    return status == 200

def test_address_struct():
    """测试 2: 创建 Address 结构体"""
    print_section("测试 2: 创建 Address 结构体")

    status, result = create_struct(
        name="Address",
        category_path="/MyTypes",
        description="地址信息",
        fields=[
            {"name": "street", "dataType": "/char", "length": 32, "comment": "街道名称"},
            {"name": "city", "dataType": "/char", "length": 32, "comment": "城市"},
            {"name": "zip", "dataType": "/int", "length": 4, "comment": "邮编"}
        ]
    )

    print(f"状态码: {status}")
    print(f"结果: {result}")
    return status == 200

def test_nested_struct():
    """测试 3: 创建嵌套结构体 Person (包含 Address 字段)"""
    print_section("测试 3: 创建嵌套结构体 Person")

    status, result = create_struct(
        name="Person",
        category_path="/MyTypes",
        description="人员信息结构体",
        fields=[
            {"name": "id", "dataType": "/int", "length": 4, "comment": "人员ID"},
            {"name": "name", "dataType": "/char", "length": 32, "comment": "姓名"},
            {"name": "age", "dataType": "/int", "length": 4, "comment": "年龄"},
            {"name": "address", "dataType": "/MyTypes/Address", "length": 68, "comment": "地址"}
        ]
    )

    print(f"状态码: {status}")
    print(f"结果: {result}")
    return status == 200

def test_complex_struct():
    """测试 4: 创建复杂结构体 Employee"""
    print_section("测试 4: 创建复杂结构体 Employee")

    status, result = create_struct(
        name="Employee",
        category_path="/Company",
        description="员工信息",
        fields=[
            {"name": "employeeId", "dataType": "/int", "length": 4, "comment": "员工ID"},
            {"name": "name", "dataType": "/char", "length": 64, "comment": "员工姓名"},
            {"name": "department", "dataType": "/char", "length": 32, "comment": "部门"},
            {"name": "salary", "dataType": "/longlong", "length": 8, "comment": "薪资"},
            {"name": "isActive", "dataType": "/bool", "length": 1, "comment": "是否在职"}
        ]
    )

    print(f"状态码: {status}")
    print(f"结果: {result}")
    return status == 200

def test_duplicate_struct():
    """测试 5: 错误处理 - 创建重复的结构体"""
    print_section("测试 5: 错误处理 - 创建重复的结构体")

    status, result = create_struct(
        name="Point",
        category_path="/Geometry",
        fields=[
            {"name": "x", "dataType": "/int", "length": 4}
        ]
    )

    print(f"状态码: {status}")
    print(f"结果: {result}")
    print(f"预期: 应该返回错误（结构体已存在）")
    return status == 400  # 预期返回 400 错误

def test_missing_name():
    """测试 6: 错误处理 - 缺少必需字段"""
    print_section("测试 6: 错误处理 - 缺少必需字段 (name)")

    url = f"{GHIDRA_SERVER}/data_types/struct"
    data = {
        "categoryPath": "/Test",
        "fields": [
            {"name": "test", "dataType": "/int", "length": 4}
        ]
    }

    try:
        response = requests.post(
            url,
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"状态码: {response.status_code}")
        print(f"结果: {response.text.strip()}")
        print(f"预期: 应该返回错误（缺少 name 字段）")
        return response.status_code == 400
    except Exception as e:
        print(f"请求失败: {e}")
        return False

def test_nonexistent_type():
    """测试 7: 错误处理 - 字段类型不存在"""
    print_section("测试 7: 错误处理 - 字段类型不存在")

    status, result = create_struct(
        name="TestStruct",
        category_path="/Test",
        fields=[
            {"name": "field1", "dataType": "/NonExistentType", "length": 4}
        ]
    )

    print(f"状态码: {status}")
    print(f"结果: {result}")
    print(f"预期: 应该返回错误（类型不存在）")
    return status == 400

def verify_structs_created():
    """测试 8: 验证结构体已创建"""
    print_section("测试 8: 验证结构体已创建")

    try:
        response = requests.get(f"{GHIDRA_SERVER}/data_types?limit=100", timeout=10)
        if response.ok:
            all_types = response.text.strip().split('\n')
            created_types = ["Point", "Address", "Person", "Employee"]
            found_types = []

            for type_name in created_types:
                for type_path in all_types:
                    if type_name in type_path:
                        found_types.append(type_name)
                        print(f"✓ 找到: {type_path}")
                        break

            print(f"\n成功创建的结构体: {len(found_types)}/{len(created_types)}")
            return len(found_types) == len(created_types)
        else:
            print(f"查询失败: {response.status_code}")
            return False
    except Exception as e:
        print(f"请求失败: {e}")
        return False

def main():
    """运行所有测试"""
    print("=" * 60)
    print("GhidraMCP 创建结构体功能测试")
    print("=" * 60)

    tests = [
        ("简单结构体", test_simple_struct),
        ("Address 结构体", test_address_struct),
        ("嵌套结构体", test_nested_struct),
        ("复杂结构体", test_complex_struct),
        ("重复结构体错误", test_duplicate_struct),
        ("缺少字段错误", test_missing_name),
        ("类型不存在错误", test_nonexistent_type),
        ("验证结构体创建", verify_structs_created),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n测试异常: {e}")
            results.append((test_name, False))

    # 打印测试结果摘要
    print_section("测试结果摘要")
    passed = 0
    failed = 0

    for test_name, result in results:
        status = "✓ 通过" if result else "✗ 失败"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n总计: {len(results)} 个测试")
    print(f"通过: {passed}")
    print(f"失败: {failed}")
    print(f"成功率: {passed / len(results) * 100:.1f}%")

    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
