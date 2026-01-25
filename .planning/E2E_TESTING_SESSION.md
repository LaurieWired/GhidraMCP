# 端到端测试会话 - 2026-01-24

## 测试环境

- **日期**: 2026-01-24
- **Ghidra 版本**: 12.0.1
- **测试功能**: Sprint 1 (基础查询) + Sprint 2 (创建数据类型)
- **测试端口**: 28382

## Task 7.1: 编译并安装插件到 Ghidra

### 步骤 1: 编译插件

```bash
cd /Users/yingdong/VSCode/ghidra/GhidraMCP
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
mvn clean package assembly:single
```

**预期结果**:
```
[INFO] BUILD SUCCESS
[INFO] Building zip: .../target/GhidraMCP-1.0-SNAPSHOT.zip
```

### 步骤 2: 验证产物

```bash
ls -lh target/GhidraMCP-*.zip
unzip -l target/GhidraMCP-1.0-SNAPSHOT.zip | head -20
```

### 步骤 3: 安装到 Ghidra

**手动操作步骤**:
1. 打开 Ghidra
2. `File` → `Install Extensions...`
3. 点击齿轮图标 → `Install from File...`
4. 选择 `target/GhidraMCP-1.0-SNAPSHOT.zip`
5. 点击 `OK` 确认安装
6. 重启 Ghidra

### 步骤 4: 验证安装

在 Ghidra 中:
- `Window` → `GhidraMCP HTTP Server`
- 应该看到服务器面板出现

**测试清单**:
- [ ] 插件编译成功
- [ ] 插件安装成功
- [ ] GhidraMCP 面板出现
- [ ] 无错误提示

---

## Task 7.2: 配置 HTTP 服务器端口

### 步骤 1: 打开测试程序

在 Ghidra 中打开任意程序(或创建新的)

### 步骤 2: 配置端口

1. `Edit` → `Tool Options` → `GhidraMCP HTTP Server`
2. 将 `Server Port` 从 `8080` 改为 `28382`
3. 点击 `Apply` 和 `OK`

### 步骤 3: 启动服务器

在 GhidraMCP 面板点击 `Start Server`

### 步骤 4: 验证服务器

```bash
curl http://localhost:28382/methods
```

**预期结果**: 返回函数列表(每行一个函数名)

**测试清单**:
- [ ] 端口配置为 28382
- [ ] 服务器启动成功
- [ ] curl 能连接到服务器
- [ ] 返回函数列表

---

## Task 7.3: 端到端测试 - 基础查询功能

### 测试 1: 列出数据类型

```bash
curl "http://localhost:28382/data_types?offset=0&limit=10"
```

**预期结果**:
```
/byte
/char
/double
/float
/int
/long
/longlong
/pointer
/qword
/short
```

**测试清单**:
- [ ] 返回前 10 个数据类型
- [ ] 每行一个路径
- [ ] 路径格式正确
- [ ] 无错误信息

### 测试 2: 获取内置类型详情

```bash
curl "http://localhost:28382/data_types/%2Fint" | jq .
```

**预期结果** (JSON):
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

**测试清单**:
- [ ] 返回有效 JSON
- [ ] path 正确
- [ ] length 正确 (4 字节)
- [ ] type 为 "BuiltIn"

### 测试 3: 搜索数据类型

```bash
curl "http://localhost:28382/data_types/search?name=int&limit=10"
```

**预期结果**: 返回所有包含 "int" 的类型
```
/int
/int[]
/pointer
/uint
/uintptr
```

**测试清单**:
- [ ] 返回包含 "int" 的类型
- [ ] 大小写不敏感工作
- [ ] 分页正确

---

## Task 7.4: 端到端测试 - 创建数据类型

### 测试 1: 创建简单结构体

```bash
curl -X POST http://localhost:28382/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Point",
    "categoryPath": "/Geometry",
    "fields": [
      {
        "name": "x",
        "dataType": "/int",
        "length": 4,
        "comment": "X coordinate"
      },
      {
        "name": "y",
        "dataType": "/int",
        "length": 4,
        "comment": "Y coordinate"
      }
    ]
  }'
```

**预期结果**:
```
Structure 'Point' created successfully in category '/Geometry'
```

### 测试 2: 验证结构体创建

```bash
curl "http://localhost:28382/data_types/%2FGeometry%2FPoint" | jq .
```

**预期结果**:
```json
{
  "path": "/Geometry/Point",
  "name": "Point",
  "type": "Structure",
  "fields": [
    {
      "name": "x",
      "offset": 0,
      "length": 4,
      "dataType": "/int"
    },
    {
      "name": "y",
      "offset": 4,
      "length": 4,
      "dataType": "/int"
    }
  ]
}
```

### 测试 3: 创建嵌套结构体 ⭐

```bash
# 步骤 1: 创建 Address
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

# 步骤 2: 创建 Person,包含 Address
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
curl "http://localhost:28382/data_types/%2FTestTypes%2FPerson" | jq .
```

**预期结果**: Person 的 address 字段应该正确引用 Address 类型

**测试清单**:
- [ ] Point 创建成功
- [ ] Address 创建成功
- [ ] Person 创建成功
- [ ] Person.address 字段类型为 /TestTypes/Address
- [ ] 字段偏移量正确

### 测试 4: 创建枚举

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
```

**验证**:
```bash
curl "http://localhost:28382/data_types/%2FTestTypes%2FColor" | jq .
```

**测试清单**:
- [ ] Color 枚举创建成功
- [ ] 包含 3 个枚举值
- [ ] 枚举值正确

### 测试 5: 创建联合体 ⭐

```bash
curl -X POST http://localhost:28382/data_types/union \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Data",
    "categoryPath": "/TestTypes",
    "fields": [
      {
        "name": "asInt",
        "dataType": "/int",
        "length": 4,
        "comment": "As integer"
      },
      {
        "name": "asFloat",
        "dataType": "/float",
        "length": 4,
        "comment": "As float"
      },
      {
        "name": "asColor",
        "dataType": "/TestTypes/Color",
        "length": 4,
        "comment": "As Color enum"
      }
    ]
  }'
```

**测试清单**:
- [ ] Data 联合体创建成功
- [ ] 包含 3 个字段
- [ ] 字段引用枚举类型正确

### 测试 6: 创建 Typedef

```bash
curl -X POST http://localhost:28382/data_types/typedef \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PersonPtr",
    "categoryPath": "/TestTypes",
    "baseDataType": "/TestTypes/Person",
    "isPointer": true
  }'
```

**测试清单**:
- [ ] PersonPtr 创建成功
- [ ] 是指针类型
- [ ] 指向 Person 结构体

---

## Task 7.5: 端到端测试 - 修改和删除

### 测试 1: 向结构体添加字段

```bash
curl -X POST http://localhost:28382/data_types/struct/add_field \
  -H "Content-Type: application/json" \
  -d '{
    "structPath": "/TestTypes/Person",
    "fieldName": "email",
    "dataType": "/char",
    "length": 32,
    "comment": "Email address"
  }'
```

**验证**:
```bash
curl "http://localhost:28382/data_types/%2FTestTypes%2FPerson" | jq .fields
```

**测试清单**:
- [ ] 字段添加成功
- [ ] Person 现在有 3 个字段
- [ ] email 字段在末尾

### 测试 2: 错误处理测试

```bash
# 尝试创建已存在的类型
curl -X POST http://localhost:28382/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{"name":"Point","categoryPath":"/Geometry","fields":[]}'
```

**预期结果**: 返回错误信息(类型已存在)

**测试清单**:
- [ ] 返回清晰错误信息
- [ ] 不会创建重复类型
- [ ] HTTP 状态码正确

---

## 测试记录模板

### Task 7.1 记录
- 编译时间: ____
- 编译结果: ✅ / ❌
- 安装是否成功: ✅ / ❌
- 遇到的问题: ____

### Task 7.2 记录
- 端口配置: ✅ / ❌
- 服务器启动: ✅ / ❌
- 测试命令输出: ____

### Task 7.3 记录
- 测试 1 (列出类型): ✅ / ❌
- 测试 2 (获取详情): ✅ / ❌
- 测试 3 (搜索): ✅ / ❌
- 发现的问题: ____

### Task 7.4 记录
- 测试 1 (简单结构体): ✅ / ❌
- 测试 2 (嵌套结构体): ✅ / ❌
- 测试 3 (枚举): ✅ / ❌
- 测试 4 (联合体): ✅ / ❌
- 测试 5 (Typedef): ✅ / ❌
- 发现的问题: ____

---

## 准备工作

在开始测试前,请确保:

1. ✅ Ghidra 12.0.1 已安装
2. ⏳ 有一个测试二进制文件(或创建新的)
3. ✅ Java 21 已配置
4. ⏳ 当前代码已编译
5. ⏳ 准备好记录测试结果

---

## 测试进度

- [ ] Task 7.1: 编译并安装
- [ ] Task 7.2: 配置端口
- [ ] Task 7.3: 基础查询测试
- [ ] Task 7.4: 创建数据类型测试
- [ ] Task 7.5: 修改和错误处理测试
- [ ] Task 7.6: MCP 工具测试
- [ ] Task 7.7: 性能测试
- [ ] Task 7.8: 真实场景测试

---
*端到端测试会话记录*
