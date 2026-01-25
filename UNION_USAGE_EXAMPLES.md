# 联合体 (Union) 使用示例

本文档提供了创建和使用联合体数据类型的实用示例。

## 目录

1. [基础示例](#基础示例)
2. [嵌套结构体](#嵌套结构体)
3. [嵌套枚举](#嵌套枚举)
4. [嵌套 Typedef](#嵌套-typedef)
5. [复杂场景](#复杂场景)
6. [错误处理](#错误处理)
7. [最佳实践](#最佳实践)

---

## 基础示例

### 示例 1: 最简单的联合体

创建一个包含整数和浮点数的联合体:

**HTTP API**:
```bash
curl -X POST http://127.0.0.1:8080/data_types/union \
  -H "Content-Type: application/json" \
  -d '{
    "name": "IntFloat",
    "categoryPath": "/Primitives",
    "description": "整数和浮点数联合体",
    "fields": [
      {
        "name": "asInt",
        "dataType": "/int",
        "length": 4,
        "comment": "作为整数访问"
      },
      {
        "name": "asFloat",
        "dataType": "/float",
        "length": 4,
        "comment": "作为浮点数访问"
      }
    ]
  }'
```

**MCP 工具**:
```python
result = create_union(
    name="IntFloat",
    category_path="/Primitives",
    description="整数和浮点数联合体",
    fields=[
        {
            "name": "asInt",
            "dataType": "/int",
            "length": 4,
            "comment": "作为整数访问"
        },
        {
            "name": "asFloat",
            "dataType": "/float",
            "length": 4,
            "comment": "作为浮点数访问"
        }
    ]
)
# 返回: "Union 'IntFloat' created successfully in category '/Primitives'"
```

### 示例 2: 多类型联合体

创建一个包含多种基本类型的联合体:

```python
result = create_union(
    name="MultiType",
    category_path="/Primitives",
    fields=[
        {"name": "asInt", "dataType": "/int", "length": 4},
        {"name": "asUInt", "dataType": "/uint", "length": 4},
        {"name": "asFloat", "dataType": "/float", "length": 4},
        {"name": "asDouble", "dataType": "/double", "length": 8},
        {"name": "asByte", "dataType": "/char", "length": 1},
        {"name": "asBytes", "dataType": "/uchar", "length": 4}
    ]
)
```

### 示例 3: 原始数据联合体

创建一个用于不同方式访问原始数据的联合体:

```python
result = create_union(
    name="RawData",
    category_path="/Utilities",
    description="原始数据联合体 - 以不同方式访问同一块内存",
    fields=[
        {"name": "asInt32", "dataType": "/int", "length": 4, "comment": "32位整数"},
        {"name": "asInt16", "dataType": "/short", "length": 2, "comment": "16位整数"},
        {"name": "asInt8", "dataType": "/char", "length": 1, "comment": "8位整数"},
        {"name": "asBytes", "dataType": "/uchar", "length": 4, "comment": "4字节数组"}
    ]
)
```

---

## 嵌套结构体

### 示例 4: 联合体包含结构体

假设已经创建了 Person 结构体:

```python
# 首先创建 Person 结构体
create_struct(
    name="Person",
    category_path="/MyTypes",
    fields=[
        {"name": "id", "dataType": "/int", "length": 4, "comment": "ID"},
        {"name": "name", "dataType": "/char", "length": 32, "comment": "姓名"},
        {"name": "age", "dataType": "/int", "length": 4, "comment": "年龄"}
    ]
)

# 然后创建包含 Person 的联合体
result = create_union(
    name="Variant",
    category_path="/MyTypes",
    description="可变类型 - 可以是 Person 或整数",
    fields=[
        {
            "name": "asPerson",
            "dataType": "/MyTypes/Person",
            "length": 40,
            "comment": "作为 Person 结构体访问"
        },
        {
            "name": "asInt",
            "dataType": "/int",
            "length": 4,
            "comment": "作为整数访问"
        }
    ]
)
```

### 示例 5: 联合体包含多个结构体

```python
# 创建多个结构体
create_struct(name="Person", category_path="/MyTypes", fields=[...])
create_struct(name="Address", category_path="/MyTypes", fields=[...])

# 创建包含多个结构体的联合体
result = create_union(
    name="DataUnion",
    category_path="/MyTypes",
    fields=[
        {"name": "asPerson", "dataType": "/MyTypes/Person", "length": 40},
        {"name": "asAddress", "dataType": "/MyTypes/Address", "length": 100}
    ]
)
```

---

## 嵌套枚举

### 示例 6: 联合体包含枚举

假设已经创建了 Color 枚举:

```python
# 首先创建 Color 枚举
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

# 然后创建包含 Color 的联合体
result = create_union(
    name="ColorValue",
    category_path="/MyTypes",
    description="颜色值 - 可以是枚举或整数",
    fields=[
        {
            "name": "asColor",
            "dataType": "/MyTypes/Color",
            "length": 4,
            "comment": "作为 Color 枚举"
        },
        {
            "name": "asInt",
            "dataType": "/int",
            "length": 4,
            "comment": "作为整数"
        }
    ]
)
```

### 示例 7: 联合体包含多个枚举

```python
# 创建多个枚举
create_enum(name="Color", category_path="/MyTypes", size=4, values=[...])
create_enum(name="Priority", category_path="/MyTypes", size=4, values=[...])

# 创建包含多个枚举的联合体
result = create_union(
    name="StatusUnion",
    category_path="/MyTypes",
    fields=[
        {"name": "asColor", "dataType": "/MyTypes/Color", "length": 4},
        {"name": "asPriority", "dataType": "/MyTypes/Priority", "length": 4},
        {"name": "asRawValue", "dataType": "/uint", "length": 4}
    ]
)
```

---

## 嵌套 Typedef

### 示例 8: 联合体包含指针 Typedef

假设已经创建了指针 Typedef:

```python
# 首先创建结构体和指针 Typedef
create_struct(name="Person", category_path="/MyTypes", fields=[...])
create_typedef(
    name="PersonPtr",
    category_path="/MyTypes",
    base_data_type="/MyTypes/Person",
    is_pointer=True
)

# 然后创建包含指针 Typedef 的联合体
result = create_union(
    name="PointerUnion",
    category_path="/MyTypes",
    description="指针联合体 - 可以指向不同类型",
    fields=[
        {
            "name": "asPersonPtr",
            "dataType": "/MyTypes/PersonPtr",
            "length": 4,
            "comment": "Person 指针"
        },
        {
            "name": "asVoidPtr",
            "dataType": "/void*",
            "length": 4,
            "comment": "void 指针"
        }
    ]
)
```

---

## 复杂场景

### 示例 9: 终极联合体 ⭐⭐⭐

创建一个包含所有类型组合的联合体:

```python
# 准备所有依赖类型
create_struct(name="Person", category_path="/MyTypes", fields=[...])
create_struct(name="Address", category_path="/MyTypes", fields=[...])
create_enum(name="Color", category_path="/MyTypes", size=4, values=[...])
create_enum(name="Priority", category_path="/MyTypes", size=4, values=[...])
create_typedef(name="PersonPtr", category_path="/MyTypes", base_data_type="/MyTypes/Person", is_pointer=True)
create_typedef(name="AddressPtr", category_path="/MyTypes", base_data_type="/MyTypes/Address", is_pointer=True)

# 创建终极联合体
result = create_union(
    name="UltimateVariant",
    category_path="/MyTypes",
    description="终极联合体 - 包含所有类型的嵌套",
    fields=[
        # 结构体
        {"name": "asPerson", "dataType": "/MyTypes/Person", "length": 40, "comment": "Person 结构体"},
        {"name": "asAddress", "dataType": "/MyTypes/Address", "length": 100, "comment": "Address 结构体"},

        # 枚举
        {"name": "asColor", "dataType": "/MyTypes/Color", "length": 4, "comment": "Color 枚举"},
        {"name": "asPriority", "dataType": "/MyTypes/Priority", "length": 4, "comment": "Priority 枚举"},

        # Typedef
        {"name": "asPersonPtr", "dataType": "/MyTypes/PersonPtr", "length": 4, "comment": "Person 指针"},
        {"name": "asAddressPtr", "dataType": "/MyTypes/AddressPtr", "length": 4, "comment": "Address 指针"},

        # 基本类型
        {"name": "asInt", "dataType": "/int", "length": 4, "comment": "整数"},
        {"name": "asFloat", "dataType": "/float", "length": 4, "comment": "浮点数"},

        # 数组
        {"name": "asBytes", "dataType": "/uchar", "length": 100, "comment": "100字节数组"}
    ]
)
```

---

## 错误处理

### 示例 10: 处理重复名称错误

```python
# 尝试创建已存在的联合体
result = create_union(
    name="IntFloat",  # 假设这个已经存在
    category_path="/Primitives",
    fields=[...]
)
# 返回: "Error: Union 'IntFloat' already exists in category '/Primitives'"
```

### 示例 11: 处理不存在的类型

```python
# 尝试使用不存在的类型
result = create_union(
    name="BadUnion",
    category_path="/MyTypes",
    fields=[
        {"name": "asBadType", "dataType": "/NonExistent/Type", "length": 4}
    ]
)
# 返回: "Error: Data type '/NonExistent/Type' not found for field 'asBadType'"
```

### 示例 12: 处理缺少必需字段

```python
# 缺少 name 字段
result = create_union(
    category_path="/MyTypes",
    fields=[...]
)
# 返回: "Error: 'name' field is required"

# 缺少 fields 数组
result = create_union(
    name="EmptyUnion",
    category_path="/MyTypes"
)
# 返回: "Error: 'fields' array is required"
```

---

## 最佳实践

### 1. 类型创建顺序

先创建基础类型,再创建依赖它们的联合体:

```python
# ✅ 正确的顺序
create_struct(name="Person", ...)
create_enum(name="Color", ...)
create_typedef(name="PersonPtr", ...)
create_union(name="Variant", fields=[...])  # 依赖上面的类型

# ❌ 错误的顺序
create_union(name="Variant", fields=[...])  # 依赖类型不存在,会失败
create_struct(name="Person", ...)
```

### 2. 字段长度匹配

确保字段长度与类型大小匹配:

```python
# ✅ 正确: 使用类型的实际大小
create_union(
    name="CorrectUnion",
    fields=[
        {"name": "asInt", "dataType": "/int", "length": 4},      # int 是 4 字节
        {"name": "asDouble", "dataType": "/double", "length": 8}  # double 是 8 字节
    ]
)

# ❌ 错误: 长度不匹配
create_union(
    name="WrongUnion",
    fields=[
        {"name": "asInt", "dataType": "/int", "length": 8}  # int 只有 4 字节!
    ]
)
```

### 3. 使用描述性注释

为所有字段添加清晰的注释:

```python
# ✅ 好的注释
create_union(
    name="NetworkData",
    fields=[
        {"name": "asInt32", "dataType": "/int", "length": 4, "comment": "32位网络整数 (大端)"},
        {"name": "asBytes", "dataType": "/uchar", "length": 4, "comment": "原始字节 (用于字节序转换)"}
    ]
)

# ❌ 没有注释
create_union(
    name="NetworkData",
    fields=[
        {"name": "asInt32", "dataType": "/int", "length": 4},
        {"name": "asBytes", "dataType": "/uchar", "length": 4}
    ]
)
```

### 4. 联合体命名约定

使用描述性名称:

```python
# ✅ 好的命名
create_union(name="IntFloatUnion", ...)
create_union(name="DataVariant", ...)
create_union(name="RawBytes", ...)

# ❌ 不好的命名
create_union(name="Union1", ...)
create_union(name="Temp", ...)
create_union(name="Thing", ...)
```

### 5. 类别路径组织

合理组织类型:

```python
# ✅ 好的组织
create_struct(name="Person", category_path="/Entities/People", ...)
create_enum(name="Color", category_path="/Enums/Graphics", ...)
create_union(name="Variant", category_path="/Unions/Variants", ...)

# ⚠️ 可以使用,但不够清晰
create_struct(name="Person", category_path="/Types", ...)
create_enum(name="Color", category_path="/Types", ...)
create_union(name="Variant", category_path="/Types", ...)
```

---

## 验证创建的类型

### 获取联合体详情

```bash
# HTTP API
curl http://127.0.0.1:8080/data_types/MyTypes/Variant

# MCP 工具
details = get_data_type("/MyTypes/Variant")
```

### 列出所有联合体

```bash
# HTTP API
curl "http://127.0.0.1:8080/data_types?offset=0&limit=100"

# MCP 工具
types = list_data_types(offset=0, limit=100)
# 然后过滤包含 "Union" 的类型
```

---

## 总结

联合体是强大的数据类型,允许在不同类型之间共享内存。在逆向工程中,它们特别有用于:

- 分析多态数据结构
- 理解变体类型
- 处理不同解释的原始数据
- 分析网络协议数据包

记住:
- 联合体的所有字段共享同一块内存
- 联合体的大小等于最大字段的大小
- 谨慎使用,确保正确理解数据的含义
