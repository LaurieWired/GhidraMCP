# 数据类型处理功能 - 详细子任务清单

## 实现策略

每个子任务遵循 **TDD 循环**:
1. 📝 **设计测试** - 包括简单和复杂场景
2. ☕ **实现 Java 端点** - 在 GhidraMCPPlugin.java
3. 🐍 **实现 MCP 工具** - 在 bridge_mcp_ghidra.py
4. 🧪 **执行测试** - curl + MCP 客户端测试
5. ✅ **验证完成** - 确保通过所有测试

## 子任务列表

### Sprint 1: 基础查询功能

#### Task 1.1: 列出所有数据类型 (GET /data_types)
**复杂度**: ⭐ 简单
**预估时间**: 30 分钟
**场景**:
- 列出前 100 个数据类型（分页）
- 列出所有数据类型（测试大数据集）
- 空结果处理
- offset 超出范围处理

**返回格式**: 纯文本，每行一个数据类型路径
```
/int
/char
/MyTypes/MyStruct
/Windows/HWND
```

**依赖**: 无
**状态**: pending

---

#### Task 1.2: 获取特定数据类型详情 (GET /data_types/{path})
**复杂度**: ⭐⭐ 中等
**预估时间**: 45 分钟
**场景**:
- 获取内置类型详情 (`/int`)
- 获取结构体详情（包含字段列表）
- 获取枚举详情（包含枚举值）
- 路径不存在处理
- ⭐ **复杂场景**: 嵌套结构体（结构体字段使用另一个自定义结构体）

**返回格式**: JSON
```json
{
  "path": "/MyTypes/Person",
  "name": "Person",
  "categoryPath": "/MyTypes",
  "length": 32,
  "description": "Person information",
  "isDeleted": false,
  "type": "Structure",
  "fields": [
    {
      "name": "id",
      "offset": 0,
      "length": 4,
      "dataType": "/int",
      "comment": "Person ID"
    },
    {
      "name": "name",
      "offset": 4,
      "length": 20,
      "dataType": "/char",
      "comment": "Person name"
    }
  ]
}
```

**依赖**: Task 1.1
**状态**: pending

---

#### Task 1.3: 搜索数据类型 (GET /data_types/search)
**复杂度**: ⭐⭐ 中等
**预估时间**: 30 分钟
**场景**:
- 按名称精确搜索
- 按名称模糊搜索
- 大小写不敏感搜索
- 空结果处理
- 分页支持

**返回格式**: 纯文本，每行一个匹配的路径
**依赖**: Task 1.1
**状态**: pending

---

### Sprint 2: 创建数据类型

#### Task 2.1: 创建结构体 (POST /data_types/struct)
**复杂度**: ⭐⭐⭐ 复杂
**预估时间**: 60 分钟
**场景**:
- 创建空结构体
- 创建带字段的结构体
- 创建在自定义分类中
- 名称冲突处理
- ⭐ **复杂场景**: 结构体字段使用另一个自定义结构体
- ⭐ **复杂场景**: 嵌套结构体（A 包含 B，B 包含 C）

**请求格式**: JSON
```json
{
  "name": "Person",
  "categoryPath": "/MyTypes",
  "fields": [
    {
      "name": "id",
      "dataType": "/int",
      "length": 4,
      "comment": "Person ID"
    },
    {
      "name": "address",
      "dataType": "/MyTypes/Address",  // 自定义结构体
      "length": 64,
      "comment": "Person address"
    }
  ]
}
```

**依赖**: Task 1.1
**状态**: pending

---

#### Task 2.2: 创建枚举 (POST /data_types/enum)
**复杂度**: ⭐⭐ 中等
**预估时间**: 45 分钟
**场景**:
- 创建空枚举
- 创建带枚举值的枚举
- 创建在自定义分类中
- 名称冲突处理

**请求格式**: JSON
```json
{
  "name": "Color",
  "categoryPath": "/MyTypes",
  "size": 4,
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
    }
  ]
}
```

**依赖**: Task 1.1
**状态**: pending

---

#### Task 2.3: 创建联合体 (POST /data_types/union)
**复杂度**: ⭐⭐⭐ 复杂
**预估时间**: 60 分钟
**场景**:
- 创建空联合体
- 创建带字段的联合体
- 创建在自定义分类中
- ⭐ **复杂场景**: 联合体字段使用自定义结构体
- ⭐ **复杂场景**: 联合体字段使用另一个自定义联合体

**请求格式**: JSON
```json
{
  "name": "Data",
  "categoryPath": "/MyTypes",
  "fields": [
    {
      "name": "asInt",
      "dataType": "/int",
      "length": 4,
      "comment": "As integer"
    },
    {
      "name": "asStruct",
      "dataType": "/MyTypes/CustomStruct",  // 自定义结构体
      "length": 32,
      "comment": "As structure"
    }
  ]
}
```

**依赖**: Task 1.1, Task 2.1
**状态**: pending

---

#### Task 2.4: 创建 Typedef (POST /data_types/typedef)
**复杂度**: ⭐ 简单
**预估时间**: 30 分钟
**场景**:
- 创建基础类型的 typedef
- 创建指针类型的 typedef
- 创建在自定义分类中
- ⭐ **复杂场景**: Typedef 指向自定义结构体

**请求格式**: JSON
```json
{
  "name": "MyIntPtr",
  "categoryPath": "/MyTypes",
  "baseDataType": "/int"
}
```

**依赖**: Task 1.1
**状态**: pending

---

### Sprint 3: 修改数据类型

#### Task 3.1: 向结构体添加字段 (POST /data_types/struct/add_field)
**复杂度**: ⭐⭐ 中等
**预估时间**: 45 分钟
**场景**:
- 向空结构体添加字段
- 向已有字段的结构体添加字段
- 添加在特定偏移量
- ⭐ **复杂场景**: 添加字段时使用自定义结构体作为类型

**请求格式**: JSON
```json
{
  "structPath": "/MyTypes/Person",
  "fieldName": "email",
  "dataType": "/MyTypes/Email",  // 自定义结构体
  "length": 32,
  "comment": "Email address"
}
```

**依赖**: Task 2.1
**状态**: pending

---

#### Task 3.2: 向枚举添加值 (POST /data_types/enum/add_value)
**复杂度**: ⭐ 简单
**预估时间**: 30 分钟
**场景**:
- 向空枚举添加值
- 向已有值的枚举添加值

**请求格式**: JSON
```json
{
  "enumPath": "/MyTypes/Color",
  "name": "BLUE",
  "value": 2,
  "comment": "Blue color"
}
```

**依赖**: Task 2.2
**状态**: pending

---

#### Task 3.3: 删除结构体字段 (POST /data_types/struct/remove_field)
**复杂度**: ⭐⭐ 中等
**预估时间**: 45 分钟
**场景**:
- 删除指定索引的字段
- 删除指定偏移量的字段
- 字段不存在处理

**请求格式**: JSON
```json
{
  "structPath": "/MyTypes/Person",
  "fieldName": "email"
}
```

**依赖**: Task 2.1
**状态**: pending

---

#### Task 3.4: 删除枚举值 (POST /data_types/enum/remove_value)
**复杂度**: ⭐ 简单
**预估时间**: 30 分钟
**场景**:
- 删除指定名称的枚举值
- 枚举值不存在处理

**请求格式**: JSON
```json
{
  "enumPath": "/MyTypes/Color",
  "name": "BLUE"
}
```

**依赖**: Task 2.2
**状态**: pending

---

### Sprint 4: 删除数据类型

#### Task 4.1: 删除数据类型 (POST /data_types/{path}/delete)
**复杂度**: ⭐⭐ 中等
**预估时间**: 45 分钟
**场景**:
- 删除自定义结构体
- 删除自定义枚举
- 删除被其他类型引用的类型（错误处理）
- 删除内置类型（错误处理）
- ⭐ **复杂场景**: 删除结构体 A，结构体 B 的字段引用了 A

**请求格式**: POST（无 body，路径包含数据类型路径）
**依赖**: Task 2.1, Task 2.2
**状态**: pending

---

### Sprint 5: 分类管理

#### Task 5.1: 列出所有分类 (GET /categories)
**复杂度**: ⭐ 简单
**预估时间**: 30 分钟
**场景**:
- 列出所有分类（包括嵌套）
- 空结果处理

**返回格式**: 纯文本，每行一个分类路径
```
/
/MyTypes
/MyTypes/Windows
/Windows
```

**依赖**: 无
**状态**: pending

---

#### Task 5.2: 创建分类 (POST /categories)
**复杂度**: ⭐ 简单
**预估时间**: 30 分钟
**场景**:
- 创建顶级分类
- 创建嵌套分类
- 分类已存在处理

**请求格式**: JSON
```json
{
  "path": "/MyTypes/Custom"
}
```

**依赖**: 无
**状态**: pending

---

#### Task 5.3: 获取分类下的数据类型 (GET /categories/{path}/data_types)
**复杂度**: ⭐⭐ 中等
**预估时间**: 45 分钟
**场景**:
- 获取分类下的数据类型
- 分页支持
- 分类不存在处理

**返回格式**: 纯文本，每行一个数据类型路径
**依赖**: Task 5.1
**状态**: pending

---

### Sprint 6: 高级查询

#### Task 6.1: 列出所有结构体 (GET /structures)
**复杂度**: ⭐ 简单
**预估时间**: 30 分钟
**场景**:
- 列出所有结构体（分页）
- 过滤非结构体类型

**返回格式**: 纯文本，每行一个路径
**依赖**: Task 1.1
**状态**: pending

---

#### Task 6.2: 列出所有枚举 (GET /enums)
**复杂度**: ⭐ 简单
**预估时间**: 30 分钟
**场景**:
- 列出所有枚举（分页）

**返回格式**: 纯文本，每行一个路径
**依赖**: Task 1.1
**状态**: pending

---

#### Task 6.3: 列出所有联合体 (GET /unions)
**复杂度**: ⭐ 简单
**预估时间**: 30 分钟
**场景**:
- 列出所有联合体（分页）

**返回格式**: 纯文本，每行一个路径
**依赖**: Task 1.1
**状态**: pending

---

## 复杂场景测试矩阵

### 嵌套数据类型测试

| 场景 | 描述 | 测试任务 |
|------|------|---------|
| 结构体包含自定义结构体 | Person 包含 Address | Task 1.2, 2.1 |
| 结构体多层嵌套 | A → B → C | Task 2.1 |
| 联合体包含自定义结构体 | Data 包含 CustomStruct | Task 2.3 |
| 联合体包含联合体 | Variant 包含另一个 Variant | Task 2.3 |
| Typedef 指向自定义结构体 | MyPtr 指向 MyStruct | Task 2.4 |
| 删除被引用的类型 | 删除 A，但 B 引用 A | Task 4.1 |

### 循环依赖测试

| 场景 | 描述 | 预期行为 |
|------|------|---------|
| 结构体自引用 | Node 包含 Node* 字段 | 允许 |
| 结构体循环引用 | A → B → A | 检测并拒绝 |

### 边界条件测试

| 场景 | 描述 | 测试任务 |
|------|------|---------|
| 空字段列表 | 创建空结构体 | Task 2.1 |
| 大字段数量 | 结构体包含 100+ 字段 | Task 2.1 |
| 大数据类型集合 | 10000+ 数据类型的分页 | Task 1.1 |
| 特殊字符名称 | 包含空格、Unicode | Task 2.1 |
| 超长名称 | 255+ 字符名称 | Task 2.1 |

## 测试工具

### HTTP 端点测试 (curl)
```bash
# 测试列出数据类型
curl "http://localhost:8080/data_types?offset=0&limit=10"

# 测试获取数据类型详情
curl "http://localhost:8080/data_types/%2FMyTypes%2FPerson"

# 测试创建结构体
curl -X POST http://localhost:8080/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","categoryPath":"/TestTypes","fields":[]}'
```

### MCP 工具测试 (Python)
```python
# 通过 MCP 客户端测试
result = mcp.call_tool("list_data_types", {"offset": 0, "limit": 10})
details = mcp.call_tool("get_data_type", {"path": "/MyTypes/Person"})
```

## 进度跟踪

| Sprint | 任务数 | 完成数 | 进度 |
|--------|--------|--------|------|
| Sprint 1: 基础查询 | 3 | 0 | 0% |
| Sprint 2: 创建数据类型 | 4 | 0 | 0% |
| Sprint 3: 修改数据类型 | 4 | 0 | 0% |
| Sprint 4: 删除数据类型 | 1 | 0 | 0% |
| Sprint 5: 分类管理 | 3 | 0 | 0% |
| Sprint 6: 高级查询 | 3 | 0 | 0% |
| **总计** | **18** | **0** | **0%** |

## 下一步

从 **Task 1.1** 开始：列出所有数据类型

---

### Sprint 7: 端到端真实测试 🧪 **需要人工协助**

**重要**: 此 Sprint 需要在真实的 Ghidra 环境中进行测试,需要人工安装和操作。

#### 前置条件检查清单
- [ ] Ghidra 12.0.1 已安装
- [ ] 有一个可以加载的测试二进制文件(建议使用简单的 ELF/PE 文件)
- [ ] Java 21 已配置
- [ ] Python 3.10+ 已安装
- [ ] MCP 客户端(如 Claude Desktop, Cline)已配置

#### Task 7.1: 编译并安装插件到 Ghidra
**复杂度**: ⭐⭐ 中等(需要人工操作)
**预估时间**: 15 分钟
**步骤**:
1. **编译插件**
   ```bash
   export JAVA_HOME=$(/usr/libexec/java_home -v 21)
   mvn clean package assembly:single
   ```
   
2. **找到生成的插件文件**
   ```bash
   ls -lh target/GhidraMCP-*.zip
   ```
   
3. **安装到 Ghidra**
   - 在 Ghidra 中: `File` → `Install Extensions` → 点击齿轮图标 → `Install from File...`
   - 选择 `target/GhidraMCP-1.0-SNAPSHOT.zip`
   - 重启 Ghidra

4. **验证安装**
   - 打开 Ghidra
   - `Window` → `GhidraMCP HTTP Server`
   - 确认服务器面板出现
   - 检查端口配置(默认 8080,改为 28382)

**状态**: pending

---

#### Task 7.2: 配置 HTTP 服务器端口
**复杂度**: ⭐ 简单
**预估时间**: 5 分钟
**步骤**:
1. 在 Ghidra 中打开任意程序
2. `Edit` → `Tool Options` → `GhidraMCP HTTP Server`
3. 将 `Server Port` 从 `8080` 改为 `28382`
4. 点击 `Apply` 和 `OK`
5. 在 GhidraMCP 面板点击 `Start Server`
6. 验证服务器启动: `curl http://localhost:28382/methods`

**预期结果**:
```bash
$ curl http://localhost:28382/methods
main
func1
func2
...
```

**状态**: pending

---

#### Task 7.3: 端到端测试 - 基础查询功能
**复杂度**: ⭐⭐ 中等
**预估时间**: 20 分钟
**测试用例**:

##### 测试 1: 列出数据类型
```bash
# 测试分页
curl "http://localhost:28382/data_types?offset=0&limit=10"

# 预期: 输出前 10 个数据类型路径
/int
/char
/short
...
```

##### 测试 2: 获取内置类型详情
```bash
# URL 编码路径
curl "http://localhost:28382/data_types/%2Fint"

# 预期: JSON 格式的类型详情
{
  "path": "/int",
  "name": "int",
  "categoryPath": "/",
  "length": 4,
  "type": "BuiltIn",
  ...
}
```

##### 测试 3: 搜索数据类型
```bash
# 搜索包含 "int" 的类型
curl "http://localhost:28382/data_types/search?name=int"

# 预期: 匹配的类型列表
/int
/uint
/longlong
/pointer
...
```

**状态**: pending

---

#### Task 7.4: 端到端测试 - 创建数据类型
**复杂度**: ⭐⭐⭐ 复杂
**预估时间**: 30 分钟
**测试用例**:

##### 测试 1: 创建简单结构体
```bash
curl -X POST http://localhost:28382/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TestStruct",
    "categoryPath": "/TestTypes",
    "fields": [
      {
        "name": "id",
        "dataType": "/int",
        "length": 4,
        "comment": "Test ID"
      },
      {
        "name": "value",
        "dataType": "/int",
        "length": 4,
        "comment": "Test value"
      }
    ]
  }'

# 预期: "Structure created successfully"
```

##### 测试 2: 验证结构体创建
```bash
# 获取结构体详情
curl "http://localhost:28382/data_types/%2FTestTypes%2FTestStruct"

# 预期: JSON 包含字段列表
{
  "path": "/TestTypes/TestStruct",
  "name": "TestStruct",
  "type": "Structure",
  "fields": [
    {"name": "id", "offset": 0, "length": 4, ...},
    {"name": "value", "offset": 4, "length": 4, ...}
  ]
}
```

##### 测试 3: 创建嵌套结构体 ⭐ **复杂场景**
```bash
# 步骤 1: 创建 Address 结构体
curl -X POST http://localhost:28382/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Address",
    "categoryPath": "/TestTypes",
    "fields": [
      {
        "name": "street",
        "dataType": "/char",
        "length": 32,
        "comment": "Street name"
      },
      {
        "name": "city",
        "dataType": "/char",
        "length": 20,
        "comment": "City name"
      }
    ]
  }'

# 步骤 2: 创建 Person 结构体,包含 Address 字段
curl -X POST http://localhost:28382/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Person",
    "categoryPath": "/TestTypes",
    "fields": [
      {
        "name": "name",
        "dataType": "/char",
        "length": 32,
        "comment": "Person name"
      },
      {
        "name": "address",
        "dataType": "/TestTypes/Address",
        "length": 52,
        "comment": "Person address (nested struct)"
      }
    ]
  }'

# 步骤 3: 验证嵌套结构
curl "http://localhost:28382/data_types/%2FTestTypes%2FPerson"

# 预期: Person 的 address 字段正确引用 Address 类型
```

**状态**: pending

---

#### Task 7.5: 端到端测试 - 修改和删除
**复杂度**: ⭐⭐⭐ 复杂
**预估时间**: 30 分钟
**测试用例**:

##### 测试 1: 向结构体添加字段
```bash
curl -X POST http://localhost:28382/data_types/struct/add_field \
  -H "Content-Type: application/json" \
  -d '{
    "structPath": "/TestTypes/TestStruct",
    "fieldName": "email",
    "dataType": "/char",
    "length": 32,
    "comment": "Email address"
  }'

# 预期: "Field added successfully"

# 验证字段已添加
curl "http://localhost:28382/data_types/%2FTestTypes%2FTestStruct"
```

##### 测试 2: 创建枚举
```bash
curl -X POST http://localhost:28382/data_types/enum \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Color",
    "categoryPath": "/TestTypes",
    "size": 4,
    "values": [
      {"name": "RED", "value": 0, "comment": "Red"},
      {"name": "GREEN", "value": 1, "comment": "Green"},
      {"name": "BLUE", "value": 2, "comment": "Blue"}
    ]
  }'

# 验证枚举创建
curl "http://localhost:28382/data_types/%2FTestTypes%2FColor"
```

##### 测试 3: 删除数据类型
```bash
# 删除测试结构体
curl -X POST http://localhost:28382/data_types/%2FTestTypes%2FTestStruct/delete

# 预期: "Data type deleted successfully"

# 验证已删除
curl "http://localhost:28382/data_types/%2FTestTypes%2FTestStruct"
# 预期: "Data type not found"
```

##### 测试 4: 错误处理 ⭐ **边界情况**
```bash
# 尝试删除内置类型(应该失败)
curl -X POST http://localhost:28382/data_types/%2Fint/delete
# 预期: "Cannot delete built-in type"

# 尝试创建已存在的类型(冲突处理)
curl -X POST http://localhost:28382/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{"name": "Person", "categoryPath": "/TestTypes", "fields": []}'
# 预期: "Type already exists" 或自动重命名
```

**状态**: pending

---

#### Task 7.6: 端到端测试 - MCP 工具集成
**复杂度**: ⭐⭐ 中等
**预估时间**: 20 分钟
**测试配置**:
1. 配置 Claude Desktop 或 Cline 连接到本地 MCP 服务器
2. 在 MCP 桥接配置中指定 Ghidra 服务器地址: `http://localhost:28382`

**测试用例**:

##### 测试 1: 通过 MCP 列出数据类型
```python
# 在 Claude Desktop/Cline 中测试
result = mcp.call_tool("list_data_types", {"offset": 0, "limit": 10})
# 预期: 返回前 10 个数据类型
```

##### 测试 2: 通过 MCP 创建结构体
```python
result = mcp.call_tool("create_struct", {
    "name": "MCPTest",
    "categoryPath": "/MCPTests",
    "fields": [
        {"name": "field1", "dataType": "/int", "length": 4}
    ]
})
# 预期: "Structure created successfully"
```

##### 测试 3: LLM 完整对话测试
```
# 在 Claude Desktop 中与 LLM 对话:
用户: "请在 Ghidra 中创建一个表示学生信息的数据结构,
     包含学号(int)、姓名(字符串32字节)、成绩(float)。"

LLM 应该:
1. 调用 create_struct 工具
2. 创建 Student 结构体
3. 包含三个字段: id, name, score
4. 确认创建成功
```

**状态**: pending

---

#### Task 7.7: 性能和稳定性测试
**复杂度**: ⭐⭐ 中等
**预估时间**: 20 分钟
**测试用例**:

##### 测试 1: 大数据集分页性能
```bash
# 测试包含 1000+ 数据类型的程序
time curl "http://localhost:28382/data_types?offset=0&limit=100"
# 预期: 响应时间 < 1 秒

# 测试深度分页
time curl "http://localhost:28382/data_types?offset=900&limit=100"
# 预期: 响应时间合理,返回正确结果
```

##### 测试 2: 并发请求测试
```bash
# 使用多个并发 curl 请求
for i in {1..10}; do
    curl "http://localhost:28382/data_types?offset=0&limit=10" &
done
wait
# 预期: 所有请求成功,无错误
```

##### 测试 3: 内存泄漏检测
```
1. 在 Ghidra 中打开任务管理器/活动监视器
2. 记录初始内存使用
3. 执行 100 次创建/删除数据类型操作
4. 检查内存是否显著增长
```

**状态**: pending

---

#### Task 7.8: 真实场景综合测试 ⭐ **终极测试**
**复杂度**: ⭐⭐⭐⭐ 非常复杂
**预估时间**: 60 分钟
**场景**: 在一个真实的二进制文件中完整使用数据类型功能

**测试步骤**:

1. **加载真实程序**
   - 在 Ghidra 中打开一个实际的 ELF/PE 文件
   - 等待自动分析完成

2. **探索现有数据类型**
   ```bash
   # 列出所有数据类型
   curl "http://localhost:28382/data_types?offset=0&limit=50"
   
   # 查找特定类型的结构体
   curl "http://localhost:28382/data_types/search?name=FILE"
   ```

3. **创建自定义数据结构**
   ```bash
   # 创建一个复杂的文件头结构体
   curl -X POST http://localhost:28382/data_types/struct \
     -H "Content-Type: application/json" \
     -d '{
       "name": "CustomFileHeader",
       "categoryPath": "/MyAnalysis",
       "fields": [
         {"name": "magic", "dataType": "/int", "length": 4, "comment": "Magic number"},
         {"name": "version", "dataType": "/int", "length": 4, "comment": "Version"},
         {"name": "timestamp", "dataType": "/longlong", "length": 8, "comment": "Timestamp"},
         {"name": "flags", "dataType": "/int", "length": 4, "comment": "Flags"}
       ]
     }'
   ```

4. **应用到实际数据**
   ```
   在 Ghidra 中:
   1. 找到二进制文件中的文件头数据
   2. 使用新创建的 CustomFileHeader 类型应用该数据
   3. 验证字段解析正确
   ```

5. **LLM 辅助逆向工程** ⭐ **完整工作流**
   ```
   用户对 Claude 说:
   "我有一个二进制文件,在地址 0x1000 处有一个数据结构。
     请帮我创建一个合适的数据类型来表示它,并应用到该地址。"
   
   LLM 应该:
   1. 使用 get_data_type 查看该地址当前类型
   2. 使用 create_struct 创建新结构体
   3. 使用 set_local_variable_type 或相关工具应用类型
   4. 确认操作成功
   ```

6. **复杂嵌套测试**
   ```bash
   # 创建嵌套的数据结构体系
   # 1. 创建 FileInfo
   # 2. 创建 SectionHeader (包含 FileInfo)
   # 3. 创建 ProgramHeader (包含 SectionHeader)
   # 4. 创建 FileFormat (包含 ProgramHeader)
   
   # 验证: 三层嵌套结构正确显示和访问
   ```

**成功标准**:
- ✅ 所有操作成功完成
- ✅ Ghidra 界面正确显示新创建的类型
- ✅ 类型可以正确应用到程序数据
- ✅ LLM 能够通过 MCP 工具完成逆向工程任务
- ✅ 无内存泄漏或崩溃
- ✅ 性能满足实际使用需求

**状态**: pending

---

## 更新后的进度跟踪

| Sprint | 任务数 | 完成数 | 进度 |
|--------|--------|--------|------|
| Sprint 1: 基础查询 | 3 | 0 | 0% |
| Sprint 2: 创建数据类型 | 4 | 0 | 0% |
| Sprint 3: 修改数据类型 | 4 | 0 | 0% |
| Sprint 4: 删除数据类型 | 1 | 0 | 0% |
| Sprint 5: 分类管理 | 3 | 0 | 0% |
| Sprint 6: 高级查询 | 3 | 0 | 0% |
| Sprint 7: 端到端真实测试 | 8 | 0 | 0% |
| **总计** | **26** | **0** | **0%** |

## Sprint 7 重要提醒

⚠️ **此 Sprint 需要人工操作,无法完全自动化**

准备工作:
1. 确保有一个可以测试的 Ghidra 环境
2. 准备一个简单的测试二进制文件
3. 预留 2-3 小时进行完整的端到端测试
4. 准备记录所有发现的问题

测试记录模板:
```
## Sprint 7 测试记录

### Task 7.1: 编译并安装
- 编译时间: ____
- 安装是否成功: ✅ / ❌
- 遇到的问题: ____

### Task 7.2: 配置端口
- 服务器启动时间: ____
- 端口是否正确: ✅ / ❌
- 测试命令输出: ____

### Task 7.3: 基础查询测试
- 测试 1 (列出类型): ✅ / ❌
- 测试 2 (获取详情): ✅ / ❌
- 测试 3 (搜索): ✅ / ❌
- 发现的问题: ____

[继续记录所有测试...]
```

---
