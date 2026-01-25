# 测试 Task 1.2: 获取特定数据类型详情

## 测试环境设置

1. 确保 Ghidra 已加载一个程序
2. 确保 GhidraMCP 插件已启动(默认端口 8080)
3. 确保 MCP 桥接服务正在运行

## 测试用例

### 1. 测试内置类型 (int)

```bash
# 使用 curl 测试 HTTP 端点
curl http://127.0.0.1:8080/data_types/int
```

**预期输出:**
```json
{
  "path": "/int",
  "name": "int",
  "categoryPath": "/",
  "length": 4,
  "description": "",
  "isDeleted": false,
  "type": "BuiltIn"
}
```

### 2. 测试其他内置类型

```bash
# 测试 float
curl http://127.0.0.1:8080/data_types/float

# 测试 char
curl http://127.0.0.1:8080/data_types/char

# 测试 void
curl http://127.0.0.1:8080/data_types/void
```

**预期输出:** 对应类型的详细信息

### 3. 测试结构体类型 (如果在程序中定义了结构体)

```bash
# 假设有一个结构体叫 MyStruct
curl http://127.0.0.1:8080/data_types/MyStruct
```

**预期输出:**
```json
{
  "path": "/MyStruct",
  "name": "MyStruct",
  "categoryPath": "/",
  "length": 32,
  "description": "My custom structure",
  "isDeleted": false,
  "type": "Structure",
  "fields": [
    {
      "name": "id",
      "offset": 0,
      "length": 4,
      "dataType": "/int",
      "comment": "Identifier"
    },
    {
      "name": "value",
      "offset": 4,
      "length": 4,
      "dataType": "/float",
      "comment": "Value"
    }
  ]
}
```

### 4. 测试枚举类型 (如果在程序中定义了枚举)

```bash
# 假设有一个枚举叫 Color
curl http://127.0.0.1:8080/data_types/Color
```

**预期输出:**
```json
{
  "path": "/Color",
  "name": "Color",
  "categoryPath": "/",
  "length": 4,
  "description": "Color enumeration",
  "isDeleted": false,
  "type": "Enum",
  "values": [
    {
      "name": "RED",
      "value": 0,
      "comment": "Red color"
    },
    {
      "name": "GREEN",
      "value": 1,
      "comment": "Green color"
    },
    {
      "name": "BLUE",
      "value": 2,
      "comment": "Blue color"
    }
  ]
}
```

### 5. 测试不存在的类型

```bash
curl http://127.0.0.1:8080/data_types/NonExistentType
```

**预期输出:**
```json
{
  "error": "Data type not found: /NonExistentType"
}
```

### 6. 测试带路径的类型

```bash
# 测试带命名空间的类型
curl http://127.0.0.1:8080/data_types/windows/BYTE
```

**预期输出:**
```json
{
  "path": "/windows/BYTE",
  "name": "BYTE",
  "categoryPath": "/windows",
  "length": 1,
  "description": "Byte",
  "isDeleted": false,
  "type": "BuiltIn"
}
```

### 7. 测试 URL 编码

```bash
# 测试包含特殊字符的类型名称
curl http://127.0.0.1:8080/data_types/My%20Type
```

**预期输出:** 正确解码的类型名称

### 8. 使用 MCP 工具测试

```python
# 通过 Python MCP 工具测试
from bridge_mcp_ghidra import get_data_type

# 测试内置类型
result = get_data_type("int")
print(result)

# 测试结构体
result = get_data_type("MyStruct")
print(result)

# 测试枚举
result = get_data_type("Color")
print(result)
```

## 验证清单

- [ ] HTTP 端点正确响应 GET 请求
- [ ] 返回的 JSON 格式正确
- [ ] 内置类型信息完整
- [ ] 结构体包含字段列表
- [ ] 枚举包含枚举值列表
- [ ] Typedef 包含基础类型信息
- [ ] 不存在的类型返回错误信息
- [ ] URL 路径正确解码
- [ ] MCP 工具正确调用 HTTP 端点
- [ ] 错误处理正常工作

## 性能测试

```bash
# 测试响应时间
time curl http://127.0.0.1:8080/data_types/int
```

**预期:** 响应时间 < 1 秒

## 边界情况测试

1. **空路径**
   ```bash
   curl http://127.0.0.1:8080/data_types/
   ```
   预期: 返回错误 "Type path is required"

2. **特殊字符**
   ```bash
   curl http://127.0.0.1:8080/data_types/type%20with%20spaces
   ```
   预期: 正确处理空格

3. **重复斜杠**
   ```bash
   curl http://127.0.0.1:8080/data_types//int
   ```
   预期: 正常处理

4. **大小写敏感**
   ```bash
   curl http://127.0.0.1:8080/data_types/INT
   ```
   预期: 根据实际类型返回结果或错误

## 实际应用场景

### 场景 1: 分析结构体布局

```bash
# 获取结构体信息以分析内存布局
curl http://127.0.0.1:8080/data_types/MyStruct | jq '.fields'
```

### 场景 2: 查找枚举值

```bash
# 获取枚举的所有可能值
curl http://127.0.0.1:8080/data_types/Color | jq '.values'
```

### 场景 3: 验证类型大小

```bash
# 检查类型的长度以确保正确的内存分配
curl http://127.0.0.1:8080/data_types/int | jq '.length'
```

## 故障排除

### 问题 1: 连接被拒绝
**解决方案:** 确认 Ghidra 正在运行且插件已启动

### 问题 2: 返回 "No program loaded"
**解决方案:** 在 Ghidra 中打开一个程序

### 问题 3: 返回 "Data type not found"
**解决方案:**
1. 使用 `list_data_types()` 查看可用的类型
2. 确认类型路径拼写正确

### 问题 4: JSON 解析错误
**解决方案:** 检查 JSON 格式,确保转义正确

## 自动化测试脚本

```bash
#!/bin/bash

# 测试脚本
BASE_URL="http://127.0.0.1:8080"

echo "测试 1: 内置类型 int"
curl -s $BASE_URL/data_types/int | jq .

echo -e "\n测试 2: 不存在的类型"
curl -s $BASE_URL/data_types/NonExistentType | jq .

echo -e "\n测试 3: 列出所有类型"
curl -s "$BASE_URL/data_types?offset=0&limit=5"

echo -e "\n所有测试完成"
```
