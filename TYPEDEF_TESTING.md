# Typedef 创建功能测试指南

## 功能概述

已成功实现 Task 2.4: 创建 Typedef (POST /data_types/typedef)

## 实现内容

### 1. HTTP 端点

**端点**: `POST /data_types/typedef`

**Content-Type**: `application/json`

**请求格式** (JSON):
```json
{
  "name": "MyIntPtr",
  "categoryPath": "/MyTypes",
  "baseDataType": "/int",
  "isPointer": false
}
```

**字段说明**:
- `name` (必需): Typedef 名称
- `categoryPath` (必需): 类别路径
- `baseDataType` (必需): 基础数据类型路径
- `isPointer` (可选): 是否为指针类型,默认 false

**返回**:
- 成功: "Typedef 'XXX' created successfully in category 'YYY'"
- 失败: "Error: ..." (带 HTTP 400 状态码)

### 2. MCP 工具

在 `bridge_mcp_ghidra.py` 中添加了 `create_typedef` 工具:

```python
@mcp.tool()
def create_typedef(name: str, category_path: str, base_data_type: str, is_pointer: bool = False) -> str:
    """创建 Typedef(类型定义)"""
```

## 测试方法

### 前置条件

1. 确保 Ghidra 正在运行
2. 确保 GhidraMCP 插件已加载并启动 HTTP 服务器 (默认端口 8080)
3. 打开一个 Ghidra 程序项目

### 测试方式 1: 使用 Bash 脚本

```bash
cd /Users/yingdong/VSCode/ghidra/GhidraMCP
./test_typedef.sh
```

### 测试方式 2: 使用 Python 脚本

```bash
cd /Users/yingdong/VSCode/ghidra/GhidraMCP
python3 test_typedef_mcp.py
```

### 测试方式 3: 手动测试 curl 命令

#### 测试 1: 创建简单的 Typedef

```bash
curl -X POST http://127.0.0.1:8080/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MyIntPtr",
    "categoryPath": "/MyTypes",
    "baseDataType": "/int"
  }'
```

**预期输出**:
```
Typedef 'MyIntPtr' created successfully in category '/MyTypes'
```

#### 测试 2: 创建指针 Typedef

首先创建一个 Person 结构体:

```bash
curl -X POST http://127.0.0.1:8080/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Person",
    "categoryPath": "/MyTypes",
    "fields": [
      {"name": "id", "dataType": "/int", "length": 4},
      {"name": "name", "dataType": "/char", "length": 32}
    ]
  }'
```

然后创建指向 Person 的指针 Typedef:

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

**预期输出**:
```
Typedef 'PersonPtr' created successfully in category '/MyTypes'
```

#### 测试 3: 验证 Typedef 已创建

```bash
# 搜索 Typedef
curl "http://127.0.0.1:8080/data_types/search?name=MyIntPtr&limit=5"

# 获取详细信息
curl "http://127.0.0.1:8080/data_types/MyTypes/MyIntPtr"
```

#### 测试 4: Typedef 指向枚举

首先创建枚举:

```bash
curl -X POST http://127.0.0.1:8080/data_types/enum \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Status",
    "categoryPath": "/MyTypes",
    "size": 4,
    "values": [
      {"name": "OK", "value": 0},
      {"name": "ERROR", "value": 1}
    ]
  }'
```

然后创建指向枚举的 Typedef:

```bash
curl -X POST http://127.0.0.1:8080/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "StatusCode",
    "categoryPath": "/MyTypes",
    "baseDataType": "/MyTypes/Status"
  }'
```

#### 测试 5: 错误处理

**基础类型不存在**:
```bash
curl -X POST http://127.0.0.1:8080/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test",
    "categoryPath": "/MyTypes",
    "baseDataType": "/NonExistentType"
  }'
```

**预期输出**:
```
Error: Base data type '/NonExistentType' not found
```

**名称冲突**:
```bash
# 重复创建 MyIntPtr
curl -X POST http://127.0.0.1:8080/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MyIntPtr",
    "categoryPath": "/MyTypes",
    "baseDataType": "/int"
  }'
```

**预期输出**:
```
Error: Typedef 'MyIntPtr' already exists in category '/MyTypes'
```

**缺少必需字段**:
```bash
curl -X POST http://127.0.0.1:8080/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TestTypedef"
  }'
```

**预期输出**:
```
Error: 'categoryPath' field is required
```

## 代码实现细节

### Java 端 (GhidraMCPPlugin.java)

1. **HTTP 端点注册** (行 472-508):
   - 在 `/data_types/typedef` 路径上注册 POST 处理器
   - 解析 JSON 请求体
   - 调用 `createTypedefFromJson()` 方法

2. **JSON 解析** (行 2566-2601):
   - `createTypedefFromJson()`: 提取和验证 JSON 字段
   - 验证必需字段 (name, categoryPath, baseDataType)
   - 解析可选字段 (isPointer)

3. **Typedef 创建** (行 2612-2683):
   - `createTypedef()`: 在事务中创建 Typedef
   - 使用 `SwingUtilities.invokeAndWait()` 确保线程安全
   - 使用 `TypedefDataType` 构造函数创建 Typedef
   - 支持普通 Typedef 和指针 Typedef

### Python 端 (bridge_mcp_ghidra.py)

1. **MCP 工具** (行 637-722):
   - `create_typedef()`: 通过 JSON 格式发送 POST 请求
   - 参数: name, category_path, base_data_type, is_pointer (可选)
   - 完整的中文文档字符串

## 测试用例覆盖

1. ✅ 简单 Typedef (int 别名)
2. ✅ 指针 Typedef (PersonPtr)
3. ✅ Typedef 指向自定义结构体
4. ✅ Typedef 指向枚举
5. ✅ Typedef 指向内置类型
6. ✅ 错误处理: 基础类型不存在
7. ✅ 错误处理: 名称冲突
8. ✅ 错误处理: 缺少必需字段

## 预期结果

所有测试应该通过,并返回相应的成功或错误消息。

## 注意事项

1. **线程安全**: 所有程序修改操作都在 `SwingUtilities.invokeAndWait()` 中执行
2. **事务处理**: 使用 `program.startTransaction()` 和 `program.endTransaction()` 确保数据一致性
3. **类型解析**: 使用现有的 `resolveDataType()` 方法解析基础类型
4. **名称唯一性**: 在创建前检查 Typedef 是否已存在
5. **错误处理**: 提供清晰的错误消息,帮助用户理解问题

## 构建和部署

### 构建 Java 插件

```bash
cd /Users/yingdong/VSCode/ghidra/GhidraMCP
mvn clean package assembly:single
```

### 在 Ghidra 中安装

1. 构建完成后,在 `target/` 目录下找到 JAR 文件
2. 将 JAR 文件复制到 Ghidra 的扩展目录:
   - macOS: `~/ghidra/Ghidra/Extensions/Ghidra`
   - Linux: `~/ghidra/Ghidra/Extensions/Ghidra`
3. 重启 Ghidra
4. 在 Ghidra 中: `File` -> `Install Extensions` -> 启用 GhidraMCP

## 常见问题

**Q: 编译失败,提示找不到 TypedefDataType**

A: 确保已正确导入: `import ghidra.program.model.data.TypedefDataType;`

**Q: 运行时提示 "No program loaded"**

A: 确保在 Ghidra 中打开了一个程序项目

**Q: 创建失败,提示基础类型不存在**

A: 使用 `GET /data_types` 查看所有可用类型,确保基础类型路径正确

## 下一步

- [ ] Task 2.3: 创建 Union (联合体)
- [ ] Task 2.5: 创建 Function Definition (函数定义)
- [ ] 完整的数据类型管理文档
