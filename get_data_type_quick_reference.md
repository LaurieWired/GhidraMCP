# get_data_type 快速参考卡

## HTTP 端点

### 端点信息
```
GET /data_types/{path}
```

### 请求示例
```bash
# 内置类型
curl http://127.0.0.1:8080/data_types/int

# 带路径的类型
curl http://127.0.0.1:8080/data_types/windows/BYTE

# URL 编码
curl http://127.0.0.1:8080/data_types/My%20Type
```

### 响应格式

#### 成功响应 (200 OK)
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

#### 错误响应
```json
{
  "error": "Data type not found: /NonExistentType"
}
```

## MCP 工具

### 工具名称
```python
get_data_type(path: str) -> str
```

### 使用示例

#### Python
```python
from bridge_mcp_ghidra import get_data_type

# 获取 int 类型
result = get_data_type("int")
print(result)

# 获取结构体
result = get_data_type("MyStruct")
print(result)
```

#### Claude Desktop
```
请获取 int 类型的详细信息
```

#### Cline / 其他 MCP 客户端
```python
# 通过 MCP 调用
result = mcp.call_tool("get_data_type", {"path": "int"})
```

## 支持的数据类型

### 1. BuiltIn (内置类型)
- int, float, char, void, bool 等
- 返回基本信息

### 2. Structure (结构体)
- 额外包含 `fields` 数组
- 每个字段包含: name, offset, length, dataType, comment

### 3. Enum (枚举)
- 额外包含 `values` 数组
- 每个值包含: name, value, comment

### 4. Union (联合体)
- 类似结构体,包含 `fields` 数组

### 5. Typedef (类型定义)
- 额外包含 `baseType` 字段

### 6. FunctionDefinition (函数定义)
- 额外包含 `returnType` 和 `hasVarArgs` 字段

### 7. Array (数组)
- 基本数组信息

### 8. Pointer (指针)
- 指针类型信息

## 常见用例

### 查看类型大小
```bash
curl http://127.0.0.1:8080/data_types/int | jq '.length'
```

### 查看结构体字段
```bash
curl http://127.0.0.1:8080/data_types/MyStruct | jq '.fields'
```

### 查看枚举值
```bash
curl http://127.0.0.1:8080/data_types/Color | jq '.values'
```

### 查找类型的描述
```bash
curl http://127.0.0.1:8080/data_types/MyType | jq '.description'
```

## 错误处理

### 常见错误

#### 1. 连接被拒绝
```
curl: (7) Failed to connect to 127.0.0.1 port 8080
```
**原因**: Ghidra 未运行或插件未启动
**解决**: 启动 Ghidra 并确保插件已加载

#### 2. No program loaded
```json
{"error": "No program loaded"}
```
**原因**: Ghidra 中未打开程序
**解决**: 在 Ghidra 中打开一个程序

#### 3. Type path is required
```json
{"error": "Type path is required"}
```
**原因**: 路径为空
**解决**: 提供有效的类型路径

#### 4. Data type not found
```json
{"error": "Data type not found: /SomeType"}
```
**原因**: 类型不存在
**解决**: 使用 `list_data_types()` 查看可用类型

## 相关工具

### list_data_types
列出所有可用的数据类型路径
```python
list_data_types(offset=0, limit=100)
```

### search_data_types
按名称搜索数据类型
```python
search_data_types(name="int", case_sensitive=False)
```

## 性能指标

- 响应时间: < 1 秒
- 内存使用: 最小化
- 并发支持: 单线程处理

## 注意事项

1. **路径格式**: 可以使用相对路径("int")或绝对路径("/int")
2. **URL 编码**: 特殊字符需要 URL 编码
3. **大小写**: 类型名称区分大小写
4. **缓存**: 不实现缓存,每次查询都是实时的
5. **线程安全**: 所有操作在 Ghidra 的正确线程上执行

## 测试命令

### 快速测试
```bash
# 运行自动化测试脚本
./test_get_data_type.sh
```

### 手动测试
```bash
# 测试内置类型
curl http://127.0.0.1:8080/data_types/int | jq .

# 测试不存在的类型
curl http://127.0.0.1:8080/data_types/NotFound | jq .

# 测试列出所有类型
curl "http://127.0.0.1:8080/data_types?offset=0&limit=5"
```

## 调试技巧

### 启用详细日志
在 Ghidra 中查看 Console 输出,所有错误和警告都会显示。

### 使用 jq 格式化 JSON
```bash
curl http://127.0.0.1:8080/data_types/int | jq .
```

### 检查 HTTP 状态码
```bash
curl -i http://127.0.0.1:8080/data_types/int
```

### 查看原始响应
```bash
curl http://127.0.0.1:8080/data_types/int
```

## 文件位置

- **Java 源代码**: `/Users/yingdong/VSCode/ghidra/GhidraMCP/src/main/java/com/lauriewired/GhidraMCPPlugin.java`
- **Python 桥接**: `/Users/yingdong/VSCode/ghidra/GhidraMCP/bridge_mcp_ghidra.py`
- **测试脚本**: `/Users/yingdong/VSCode/ghidra/GhidraMCP/test_get_data_type.sh`
- **测试文档**: `/Users/yingdong/VSCode/ghidra/GhidraMCP/test_data_type_details.md`

## 版本信息

- **实现日期**: 2026-01-24
- **Ghidra 版本**: 11.3.2
- **Java 版本**: JDK 21
- **Python 版本**: 3.10+
- **MCP 版本**: 1.2.0+

## 联系与支持

如有问题或建议,请查看:
- 实现总结: `TASK_1.2_IMPLEMENTATION_SUMMARY.md`
- 测试文档: `test_data_type_details.md`
- 项目 README: `README.md`
