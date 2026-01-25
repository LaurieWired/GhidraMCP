# Typedef 创建功能 - 代码片段

## 1. Java HTTP 端点实现

### Import 语句
```java
// 添加到 GhidraMCPPlugin.java 第 47 行
import ghidra.program.model.data.TypedefDataType;
```

### HTTP 端点注册 (第 472-508 行)
```java
// 创建 Typedef 数据类型 - 必须在 /data_types 之前注册
server.createContext("/data_types/typedef", exchange -> {
    if (!"POST".equals(exchange.getRequestMethod())) {
        try {
            sendResponse(exchange, "Method not allowed. Use POST.", 405);
        } catch (IOException e) {
            Msg.error(this, "Failed to send error response", e);
        }
        return;
    }

    // 解析 JSON 请求体
    String requestBody;
    try {
        byte[] body = exchange.getRequestBody().readAllBytes();
        requestBody = new String(body, StandardCharsets.UTF_8);
    } catch (IOException e) {
        Msg.error(this, "Failed to read request body", e);
        try {
            sendResponse(exchange, "Failed to read request body", 500);
        } catch (IOException ex) {
            Msg.error(this, "Failed to send error response", ex);
        }
        return;
    }

    String result = createTypedefFromJson(requestBody);
    try {
        if (result.startsWith("Error")) {
            sendResponse(exchange, result, 400);
        } else {
            sendResponse(exchange, result);
        }
    } catch (IOException e) {
        Msg.error(this, "Failed to send response", e);
    }
});
```

### JSON 解析方法 (第 2566-2601 行)
```java
/**
 * 从 JSON 字符串创建 Typedef 数据类型
 */
private String createTypedefFromJson(String jsonStr) {
    Program program = getCurrentProgram();
    if (program == null) {
        return "Error: No program loaded";
    }

    // 简单的 JSON 解析 (不使用外部库)
    try {
        // 提取必需字段
        String name = extractJsonString(jsonStr, "name");
        if (name == null || name.isEmpty()) {
            return "Error: 'name' field is required";
        }

        String categoryPath = extractJsonString(jsonStr, "categoryPath");
        if (categoryPath == null || categoryPath.isEmpty()) {
            return "Error: 'categoryPath' field is required";
        }

        String baseDataType = extractJsonString(jsonStr, "baseDataType");
        if (baseDataType == null || baseDataType.isEmpty()) {
            return "Error: 'baseDataType' field is required";
        }

        // 提取可选字段 isPointer
        String isPointerStr = extractJsonString(jsonStr, "isPointer");
        boolean isPointer = isPointerStr != null && isPointerStr.equalsIgnoreCase("true");

        // 创建 Typedef
        return createTypedef(program, categoryPath, name, baseDataType, isPointer);

    } catch (Exception e) {
        Msg.error(this, "Error creating typedef from JSON", e);
        return "Error: Invalid JSON format - " + e.getMessage();
    }
}
```

### Typedef 创建方法 (第 2612-2683 行)
```java
/**
 * 创建 Typedef 数据类型
 */
private String createTypedef(Program program, String categoryPathStr, String name,
                            String baseDataTypeStr, boolean isPointer) {
    final AtomicBoolean success = new AtomicBoolean(false);
    final AtomicString errorMsg = new AtomicString("");

    try {
        SwingUtilities.invokeAndWait(() -> {
            int tx = program.startTransaction("Create typedef: " + name);
            try {
                DataTypeManager dtm = program.getDataTypeManager();
                CategoryPath catPath = new CategoryPath(categoryPathStr);

                // 检查 Typedef 是否已存在
                String existingPath = catPath.getPath() + (catPath.getPath().endsWith("/") ? "" : "/") + name;
                if (dtm.getDataType(existingPath) != null) {
                    errorMsg.set("Error: Typedef '" + name + "' already exists in category '" + categoryPathStr + "'");
                    return;
                }

                // 解析基础数据类型
                DataType baseType = resolveDataType(dtm, baseDataTypeStr);
                if (baseType == null) {
                    errorMsg.set("Error: Base data type '" + baseDataTypeStr + "' not found");
                    return;
                }

                // 创建 Typedef
                DataType typedef;
                if (isPointer) {
                    // 创建指针 Typedef
                    typedef = new TypedefDataType(
                        catPath,
                        name,
                        new PointerDataType(baseType)
                    );
                } else {
                    // 创建普通 Typedef
                    typedef = new TypedefDataType(
                        catPath,
                        name,
                        baseType
                    );
                }

                // 添加到数据类型管理器
                DataType addedTypedef = dtm.addDataType(typedef, null);
                if (addedTypedef != null) {
                    success.set(true);
                    Msg.info(this, "Created typedef: " + addedTypedef.getPathName());
                } else {
                    errorMsg.set("Error: Failed to add typedef to data type manager");
                }
            } catch (Exception e) {
                errorMsg.set("Error: Failed to create typedef: " + e.getMessage());
                Msg.error(this, "Failed to create typedef", e);
            } finally {
                program.endTransaction(tx, success.get());
            }
        });
    } catch (InterruptedException | InvocationTargetException e) {
        Msg.error(this, "Failed to execute typedef creation on Swing thread", e);
        return "Error: Failed to execute typedef creation: " + e.getMessage();
    }

    if (success.get()) {
        return "Typedef '" + name + "' created successfully in category '" + categoryPathStr + "'";
    } else {
        return errorMsg.get();
    }
}
```

## 2. Python MCP 工具实现

### MCP 工具定义 (第 637-722 行)
```python
@mcp.tool()
def create_typedef(name: str, category_path: str, base_data_type: str, is_pointer: bool = False) -> str:
    """
    创建 Typedef(类型定义)。

    此函数在 Ghidra 中创建一个新的 Typedef 数据类型。Typedef 为现有类型
    创建别名,常用于提高代码可读性或简化复杂类型。

    Args:
        name: Typedef 名称 (必需)
              例如: "MyIntPtr", "PersonPtr", "UserID"

        category_path: 类别路径 (必需)
                      Typedef 所在的类别路径,例如: "/", "/MyTypes", "/System"

        base_data_type: 基础数据类型 (必需)
                       Typedef 指向的基础类型,可以是:
                       - 基本类型: "/int", "/uint", "/char", "/void"
                       - 自定义类型: "/MyTypes/Person", "/windows/BYTE"
                       - 其他已存在的任何类型

        is_pointer: 是否为指针类型 (可选,默认 False)
                   如果为 True,创建一个指针类型的 Typedef
                   例如: isPointer=True 时,相当于创建 "Person*" 的别名

    Returns:
        成功: "Typedef 'XXX' created successfully in category 'YYY'"
        失败: 错误消息,包含失败原因
    """
    import json

    # 构建请求数据
    data = {
        "name": name,
        "categoryPath": category_path,
        "baseDataType": base_data_type,
        "isPointer": is_pointer
    }

    # 发送 POST 请求
    try:
        url = urljoin(ghidra_server_url, "data_types/typedef")
        response = requests.post(
            url,
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.encoding = 'utf-8'

        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"
```

## 3. 使用示例

### 示例 1: 创建简单的 Typedef
```bash
curl -X POST http://127.0.0.1:8080/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MyIntPtr",
    "categoryPath": "/MyTypes",
    "baseDataType": "/int"
  }'
```

### 示例 2: 创建指针 Typedef
```bash
curl -X POST http://127.0.0.1:8080/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PersonPtr",
    "categoryPath": "/MyTypes",
    "baseDataType": "/MyTypes/Person",
    "isPointer": true
  }'
```

### 示例 3: 在 Python 中使用
```python
# 使用 MCP 工具
result = create_typedef(
    name="UserID",
    category_path="/System",
    base_data_type="/uint"
)
print(result)
# 输出: Typedef 'UserID' created successfully in category '/System'
```

## 4. 关键点总结

### 4.1 TypedefDataType 构造函数
```java
// 普通 Typedef
new TypedefDataType(CategoryPath, String name, DataType baseType)

// 指针 Typedef
new TypedefDataType(CategoryPath, String name, PointerDataType baseType)
```

### 4.2 线程安全
```java
SwingUtilities.invokeAndWait(() -> {
    int tx = program.startTransaction("...");
    try {
        // 修改操作
    } finally {
        program.endTransaction(tx, success.get());
    }
});
```

### 4.3 错误处理
- 名称冲突检查
- 基础类型验证
- 必需字段验证
- 事务回滚

### 4.4 类型解析
使用 `resolveDataType()` 方法:
```java
DataType baseType = resolveDataType(dtm, baseDataTypeStr);
```
支持:
- 内置类型: `/int`, `/uint`, `/char`, `/void`
- 自定义类型: `/MyTypes/Person`
- 指针类型: 通过 `isPointer` 参数

## 5. 测试验证

### 运行测试
```bash
# Bash 测试
./test_typedef.sh

# Python 测试
python3 test_typedef_mcp.py
```

### 验证结果
```bash
# 搜索 Typedef
curl "http://127.0.0.1:8080/data_types/search?name=MyIntPtr"

# 获取详细信息
curl "http://127.0.0.1:8080/data_types/MyTypes/MyIntPtr"
```

## 6. 文件清单

- **Java 实现**: `src/main/java/com/lauriewired/GhidraMCPPlugin.java`
- **Python 实现**: `bridge_mcp_ghidra.py`
- **Bash 测试**: `test_typedef.sh`
- **Python 测试**: `test_typedef_mcp.py`
- **测试文档**: `TYPEDEF_TESTING.md`
- **实现总结**: `IMPLEMENTATION_SUMMARY_TYPEDEF.md`
- **快速参考**: `typedef_quick_reference.txt`
