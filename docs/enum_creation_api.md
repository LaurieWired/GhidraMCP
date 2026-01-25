# 枚举数据类型创建 API 文档

## 概述

本文档描述了 GhidraMCP 中创建枚举数据类型的 API 接口和使用方法。

## HTTP 端点

### POST /data_types/enum

在 Ghidra 中创建一个新的枚举数据类型。

**请求方法**: POST
**Content-Type**: application/json
**URL**: `http://127.0.0.1:8080/data_types/enum`

### 请求格式

```json
{
  "name": "枚举名称",
  "categoryPath": "/类别路径",
  "size": 4,
  "description": "枚举描述(可选)",
  "values": [
    {
      "name": "枚举值名称",
      "value": 枚举值,
      "comment": "枚举值注释(可选)"
    }
  ]
}
```

### 参数说明

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| name | string | ✅ | 枚举类型的名称 |
| categoryPath | string | ✅ | 枚举所在的类别路径,例如 `/`, `/MyTypes` |
| size | integer | ✅ | 枚举值的大小(字节数),必须是 1, 2, 4, 或 8 |
| description | string | ❌ | 枚举类型的描述 |
| values | array | ✅ | 枚举值列表,至少包含一个值 |

### 枚举值对象

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| name | string | ✅ | 枚举值的名称 |
| value | integer | ✅ | 枚举值(整数或长整数) |
| comment | string | ❌ | 枚举值的注释 |

### 响应

**成功** (200):
```
Enum created successfully
```

**失败** (400):
```
Error: 错误原因描述
```

## 使用示例

### 示例 1: 简单枚举

```bash
curl -X POST http://127.0.0.1:8080/data_types/enum \
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
  }'
```

### 示例 2: 带注释的枚举

```bash
curl -X POST http://127.0.0.1:8080/data_types/enum \
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
  }'
```

### 示例 3: 1字节枚举

```bash
curl -X POST http://127.0.0.1:8080/data_types/enum \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Status",
    "categoryPath": "/",
    "size": 1,
    "values": [
      {"name": "OK", "value": 0},
      {"name": "ERROR", "value": 1},
      {"name": "PENDING", "value": 2}
    ]
  }'
```

### 示例 4: 8字节枚举

```bash
curl -X POST http://127.0.0.1:8080/data_types/enum \
  -H "Content-Type: application/json" \
  -d '{
    "name": "LargeValue",
    "categoryPath": "/Test",
    "size": 8,
    "values": [
      {"name": "MIN", "value": 0},
      {"name": "MAX", "value": 9223372036854775807}
    ]
  }'
```

## MCP 工具

### create_enum

通过 MCP 协议创建枚举数据类型。

#### 参数

- `name` (str): 枚举类型名称
- `category_path` (str): 类别路径
- `size` (int): 枚举大小 (1, 2, 4, 或 8)
- `values` (list): 枚举值列表

#### 返回值

成功或错误消息

#### 示例

```python
create_enum(
    name="Color",
    category_path="/MyTypes",
    size=4,
    values=[
        {"name": "RED", "value": 0},
        {"name": "GREEN", "value": 1},
        {"name": "BLUE", "value": 2}
    ]
)
```

## 错误处理

### 常见错误

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| `Error: 'name' field is required` | 缺少枚举名称 | 提供 `name` 字段 |
| `Error: 'categoryPath' field is required` | 缺少类别路径 | 提供 `categoryPath` 字段 |
| `Error: 'size' must be 1, 2, 4, or 8` | 无效的 size 值 | 使用 1, 2, 4, 或 8 |
| `Error: At least one enum value is required` | values 数组为空 | 至少添加一个枚举值 |
| `Error: Duplicate enum value name: XXX` | 枚举值名称重复 | 修改枚举值名称使其唯一 |
| `Error: Enum '/path/to/Enum' already exists` | 枚举已存在 | 使用不同的名称或路径 |

### 错误响应示例

```json
Error: 'size' must be 1, 2, 4, or 8
```

```json
Error: Enum '/MyTypes/Color' already exists
```

## 验证创建的枚举

### 获取枚举详情

```bash
curl "http://127.0.0.1:8080/data_types/MyTypes/Color"
```

**响应示例**:
```json
{
  "path": "/MyTypes/Color",
  "name": "Color",
  "categoryPath": "/MyTypes",
  "length": 4,
  "description": "",
  "isDeleted": false,
  "type": "Enum",
  "values": [
    {"name": "RED", "value": 0},
    {"name": "GREEN", "value": 1},
    {"name": "BLUE", "value": 2}
  ]
}
```

### 列出所有数据类型

```bash
curl "http://127.0.0.1:8080/data_types?offset=0&limit=100"
```

## 测试

运行完整的测试套件:

```bash
cd /Users/yingdong/VSCode/ghidra/GhidraMCP/tests
./test_enum_creation.sh
```

## 技术实现

### Ghidra API 使用

- `EnumDataType`: 枚举数据类型类
- `CategoryPath`: 类别路径类
- `DataTypeManager.addDataType()`: 添加数据类型到管理器
- `EnumDataType.add()`: 添加枚举值
- `EnumDataType.setComment()`: 设置枚举值注释

### 事务处理

所有枚举创建操作都在 Ghidra 事务中执行,确保数据一致性:

```java
int tx = program.startTransaction("Create enum data type");
try {
    // 创建枚举
} finally {
    program.endTransaction(tx, success);
}
```

### 线程安全

使用 `SwingUtilities.invokeAndWait()` 确保在正确的线程中执行:

```java
SwingUtilities.invokeAndWait(() -> {
    // 枚举创建代码
});
```

## 相关文档

- [Sprint 1 实现文档](../../.planning/sprint_1_data_type_management.md)
- [完成报告](../../.planning/task_2_2_completion_report.md)
- [测试脚本](../../tests/test_enum_creation.sh)

## 版本历史

- **v1.0** (2024): 初始实现,支持基本的枚举创建功能
