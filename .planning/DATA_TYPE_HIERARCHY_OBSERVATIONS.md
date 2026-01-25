# Ghidra 数据类型层次结构观察

## 实际创建位置 vs 请求的 categoryPath

### 观察 1: 当 `categoryPath: "/engine"` 时

**请求**:
```json
{
  "name": "Point",
  "categoryPath": "/engine",
  "fields": [{"name": "x", "dataType": "/int", "length": 4}]
}
```

**实际创建位置**:
```
Data Types
└── engine (程序名)
    └── engine (categoryPath)
        └── Point ← 类型在这里
```

**完整路径**: `/engine/Point`

### 观察 2: 当 `categoryPath: "/"` 时

**请求**:
```json
{
  "name": "TestPoint",
  "categoryPath": "/",
  "fields": [{"name": "x", "dataType": "/int", "length": 4}]
}
```

**实际创建位置**:
```
Data Types
└── engine (程序名)
    └── MyTypes (代码中自动转换)
        └── TestPoint ← 类型在这里
```

**完整路径**: `/MyTypes/TestPoint`

**代码逻辑** (第 2469-2473 行):
```java
if (categoryPath.equals("/") || categoryPath.isEmpty()) {
    // 根路径不能直接使用，创建一个默认分类
    catPath = new CategoryPath("/MyTypes");
    Msg.info(this, "根路径 / 不支持，自动使用 /MyTypes");
} else {
    catPath = new CategoryPath(categoryPath);
}
```

## 关键发现

### 1. 程序名作为根容器
Ghidra 的数据类型管理器以**程序名**作为根容器：
- 所有数据类型都在程序名之下
- `categoryPath` 是相对于程序名的路径

### 2. categoryPath 的实际行为
- `categoryPath: "/engine"` → 创建 `engine` 分类，然后在其中创建类型
- `categoryPath: "/"` → 代码自动转换为 `/MyTypes`

### 3. 数据类型的完整路径
数据类型的完整路径是：`/<程序名>/<categoryPath>/<类型名>`

但 Ghidra 的 `DataType.getPathName()` 返回：`/<categoryPath>/<类型名>`

## 对获取类型 API 的影响

### GET /data_types/{path} 的行为

当用户请求 `/data_types/engine/Point` 时：
- **用户期望**: 获取 engine 分类下的 Point 类型
- **实际路径**: `/engine/Point`
- **Ghidra 内部**: 需要查找程序名下的 engine 分类

### 需要考虑的情况

1. **直接路径查询**:
   - 用户请求: `/data_types/engine/Point`
   - 需要处理: 程序名前缀

2. **根路径查询**:
   - 用户请求: `/data_types/MyTypes/TestPoint`
   - 实际位置: `/MyTypes/TestPoint`（自动转换）

3. **内置类型查询**:
   - 用户请求: `/data_types/int`
   - 实际位置: `/int`（在根分类下）

## 建议的改进

### 1. 在获取类型时处理程序名
```java
// 当前实现 (可能需要调整)
DataType dataType = dtm.getDataType("/" + typePath);

// 改进后
String fullPath = typePath.startsWith("/") ? typePath : "/" + typePath;
DataType dataType = dtm.getDataType(fullPath);
```

### 2. 在列表中显示完整信息
```json
{
  "path": "/engine/Point",
  "name": "Point",
  "categoryPath": "/engine",
  "program": "engine"
}
```

### 3. 支持按程序名过滤
```bash
GET /data_types?program=engine&categoryPath=/engine
```

## 测试用例

### 测试 1: 创建并查询
```bash
# 1. 创建类型
curl -X POST http://localhost:28382/data_types/struct \
  -d '{"name":"Test1","categoryPath":"/testcat","fields":[{"name":"x","dataType":"/int","length":4}]}'

# 2. 查询类型
curl http://localhost:28382/data_types/testcat/Test1

# 预期返回
{
  "path": "/testcat/Test1",
  "name": "Test1",
  "categoryPath": "/testcat",
  "type": "Structure"
}
```

### 测试 2: 根路径自动转换
```bash
# 1. 创建类型（使用根路径）
curl -X POST http://localhost:28382/data_types/struct \
  -d '{"name":"Test2","categoryPath":"/","fields":[{"name":"x","dataType":"/int","length":4}]}'

# 2. 查询类型（使用转换后的路径）
curl http://localhost:28382/data_types/MyTypes/Test2

# 预期返回
{
  "path": "/MyTypes/Test2",
  "name": "Test2",
  "categoryPath": "/MyTypes",
  "note": "Automatically converted from root path"
}
```

## 数据类型层次结构示例

```
Data Types (Program: engine)
├── / (内置类型根)
│   ├── int
│   ├── char
│   └── void
│
├── engine (用户创建的分类)
│   └── Point
│
└── MyTypes (默认分类，从 / 自动转换)
    └── TestPoint
```

## 后续工作

1. ✅ 创建结构体 - 已完成
2. ⏳ 验证获取类型 API 是否正确处理这些路径
3. ⏳ 添加类型列表时显示完整的 categoryPath
4. ⏳ 文档化 categoryPath 的行为和自动转换规则

---

*记录时间: 2026-01-24 22:35*
*基于用户的实际测试观察*
