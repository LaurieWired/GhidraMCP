# Findings & Decisions - 数据类型处理功能
<!--
  WHAT: 数据类型处理功能的知识库
  WHY: 存储 Ghidra 数据类型 API 的所有研究发现
  WHEN: 基于 3 个并行 Explore agents 的研究结果创建
-->

## Requirements
<!--
  WHAT: 用户要求的功能需求
-->
根据用户需求和讨论:

### 功能需求
1. **列出所有数据类型** - 支持过滤和分页
2. **获取特定数据类型的详细信息** - 包括结构体字段、枚举值等
3. **创建新数据类型** - 结构体、枚举、联合体、typedef、函数定义
4. **修改数据类型** - 添加/删除字段、修改属性
5. **删除数据类型**
6. **分类管理** - 创建、列出、删除分类
7. **高级查询** - 按类型、名称、大小、分类等过滤

### 技术需求
- 遵循 GhidraMCP 现有的 API 设计模式
- 使用事务和线程安全模式
- 提供清晰的 MCP 工具文档
- 支持分页以提高性能
- 完善的错误处理

## Research Findings
<!--
  WHAT: 来自 3 个并行 Explore agents 的关键发现
  WHY: 所有研究结果都经过交叉验证,高度一致
-->

### 核心接口总结

#### 1. DataTypeManager (数据类型管理器)
**位置**: `ghidra.program.model.data.DataTypeManager`

**关键方法**:
```java
// 查询和枚举
Iterator<DataType> getAllDataTypes()
void getAllDataTypes(List<DataType> list)
Iterator<Structure> getAllStructures()
Iterator<Composite> getAllComposites()
Iterator<FunctionDefinition> getAllFunctionDefinitions()

// 按路径获取
DataType getDataType(String path)  // 例如 "/int", "/MyTypes/MyStruct"
DataType getDataType(CategoryPath path, String name)

// 搜索
void findDataTypes(String query, List<DataType> results)
void findDataTypes(String query, List<DataType> results, boolean caseSensitive, TaskMonitor monitor)

// 创建和添加
DataType addDataType(DataType dataType, DataTypeConflictHandler handler)
void addDataTypes(Collection<DataType> types, DataTypeConflictHandler handler, TaskMonitor monitor)

// 删除和替换
boolean remove(DataType dataType)
void remove(List<DataType> types, TaskMonitor monitor)
DataType replaceDataType(DataType oldType, DataType newType, boolean replaceInstances)

// 分类管理
Category getCategory(CategoryPath path)
Category createCategory(CategoryPath categoryPath)
boolean containsCategory(CategoryPath path)

// 事务管理
int startTransaction(String description)
boolean endTransaction(int transactionID, boolean commit)

// 其他
boolean isFavorite(DataType dataType)
void setFavorite(DataType dataType, boolean isFavorite)
List<DataType> getFavorites()
```

#### 2. DataType (数据类型基接口)
**关键方法**:
```java
// 基本信息
String getName()
String getPathName()
CategoryPath getCategoryPath()
DataTypePath getDataTypePath()

// 属性
int getLength()
String getDescription()
void setDescription(String description)

// 状态
boolean isDeleted()
boolean isEquivalent(DataType dataType)
boolean dependsOn(DataType dataType)

// 操作
DataType clone(DataTypeManager dtm)
void setName(String name)
void setNameAndCategory(CategoryPath path, String name)
```

#### 3. Category (分类)
**关键方法**:
```java
// 分类操作
Category createCategory(String name)
Category getCategory(String name)
Category[] getCategories()
boolean removeCategory(String name, TaskMonitor monitor)

// 数据类型操作
DataType getDataType(String name)
DataType[] getDataTypes()
List<DataType> getDataTypesByBaseName(String name)
DataType addDataType(DataType dataType, DataTypeConflictHandler handler)
boolean remove(DataType dataType, TaskMonitor monitor)
```

#### 4. CategoryPath (分类路径)
**构造**:
```java
CategoryPath(String path)  // "/Category1/Category2"
CategoryPath(CategoryPath parent, String... names)
CategoryPath.ROOT  // 根路径
```

**关键方法**:
```java
String getPath()
String getName()
CategoryPath getParent()
boolean isRoot()
CategoryPath extend(String... names)
String[] getPathElements()
```

#### 5. Structure (结构体)
**构造**:
```java
StructureDataType(String name, int length)
StructureDataType(CategoryPath path, String name, int length, DataTypeManager dtm)
```

**字段操作**:
```java
// 添加字段
DataTypeComponent add(DataType dataType, int length, String fieldName, String comment)
DataTypeComponent insertAtOffset(int offset, DataType dataType, int length, String fieldName, String comment)

// 删除字段
void delete(int index)
void deleteAtOffset(int offset)

// 修改字段
DataTypeComponent replace(int index, DataType dataType, int length, String fieldName, String comment)

// 查询字段
int getNumComponents()
DataTypeComponent getComponent(int index)
DataTypeComponent getComponentAt(int offset)
DataTypeComponent[] getComponents()
```

#### 6. Enum (枚举)
**构造**:
```java
EnumDataType(String name, int size)  // size: 1, 2, 4, or 8
EnumDataType(CategoryPath path, String name, int size, DataTypeManager dtm)
```

**枚举值操作**:
```java
// 添加/删除
void add(String name, long value)
void add(String name, long value, String comment)
void remove(String name)

// 查询
String getName(long value)
long getValue(String name)
String[] getNames()
long[] getValues()
int getCount()
boolean contains(String name)
```

#### 7. Union (联合体)
**构造**:
```java
UnionDataType(String name)
UnionDataType(CategoryPath path, String name, DataTypeManager dtm)
```
操作方法与 Structure 类似

#### 8. FunctionDefinition (函数定义)
**构造**:
```java
FunctionDefinitionDataType(String name)
FunctionDefinitionDataType(CategoryPath path, String name, DataTypeManager dtm)
```

**操作**:
```java
void setReturnType(DataType dataType)
void setArguments(ParameterDefinition... parameters)
void setCallingConvention(String name)
void setVarArgs(boolean hasVarArgs)
DataType getReturnType()
ParameterDefinition[] getArguments()
```

#### 9. DataTypeComponent (数据类型组件/字段)
**关键方法**:
```java
DataType getDataType()
int getOffset()
int getLength()
String getFieldName()
void setFieldName(String name)
String getComment()
void setComment(String comment)
boolean isBitFieldComponent()
```

#### 10. DataTypeConflictHandler (冲突处理)
**预定义处理器**:
```java
DEFAULT_HANDLER                      // 默认处理
REPLACE_HANDLER                      // 替换现有类型
KEEP_HANDLER                         // 保留现有类型
REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER  // 智能处理
```

### 现有 GhidraMCP 代码模式

#### 数据类型解析 (第 1442-1513 行)
```java
private DataType resolveDataType(DataTypeManager dtm, String typeName) {
    // 尝试直接获取
    DataType dataType = dtm.getDataType("/" + typeName);
    if (dataType != null) return dataType;

    // 在所有分类中搜索
    dataType = findDataTypeByNameInAllCategories(dtm, typeName);
    if (dataType != null) return dataType;

    // 处理 Windows 指针类型 (PXXX)
    if (typeName.startsWith("P") && typeName.length() > 1) {
        String baseTypeName = typeName.substring(1);
        DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
        if (baseType != null) {
            return new PointerDataType(baseType);
        }
    }

    return null;
}
```

#### 跨分类搜索 (第 1519-1548 行)
```java
private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
    DataType result = searchByNameInAllCategories(dtm, typeName);
    if (result != null) return result;
    return searchByNameInAllCategories(dtm, typeName.toLowerCase());
}

private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
    Iterator<DataType> allTypes = dtm.getAllDataTypes();
    while (allTypes.hasNext()) {
        DataType dt = allTypes.next();
        if (dt.getName().equals(name)) {
            return dt;
        }
    }
    return null;
}
```

### 内置类型路径
所有内置类型都在根路径 `/` 下:
- 整数: `/byte`, `/char`, `/short`, `/int`, `/longlong`, `/uchar`, `/ushort`, `/uint`, `/ulonglong`
- 浮点: `/float`, `/double`
- 其他: `/void`, `/bool`, `/undefined1` 到 `/undefined8`

## Technical Decisions
| Decision | Rationale |
|----------|-----------|
| 保持现有 API 设计模式 | 与 GhidraMCP 现有端点一致,所有修改操作使用 POST |
| 在 Java 端实现分页 | 使用 Iterator 的懒加载特性,减少数据传输 |
| 使用字符串路径 | 与 Ghidra API 一致,简洁易用 |
| 支持多种查询维度 | 按类型、分类、名称、大小等多维度过滤 |
| 事务处理必须使用 SwingUtilities | 遵循现有代码的线程安全模式 |
| 使用 DataTypeConflictHandler.DEFAULT_HANDLER | 默认冲突处理策略,简单可靠 |
| 优先实现核心功能 | 第一版实现常用操作,高级功能(如批量操作)后续迭代 |

## Proposed HTTP API Endpoints

### 基础查询
- `GET /data_types?offset=0&limit=100` - 列出所有数据类型(分页)
- `GET /data_types/{path}` - 获取特定数据类型的详细信息
- `GET /data_types/search?name={query}` - 按名称搜索数据类型

### 类型特定查询
- `GET /structures?offset=0&limit=100` - 列出所有结构体
- `GET /enums?offset=0&limit=100` - 列出所有枚举
- `GET /unions?offset=0&limit=100` - 列出所有联合体
- `GET /typedefs?offset=0&limit=100` - 列出所有类型定义
- `GET /function_definitions?offset=0&limit=100` - 列出所有函数定义

### 创建操作
- `POST /data_types/struct` - 创建结构体
- `POST /data_types/enum` - 创建枚举
- `POST /data_types/union` - 创建联合体
- `POST /data_types/typedef` - 创建类型定义
- `POST /data_types/function_def` - 创建函数定义

### 修改操作
- `POST /data_types/struct/add_field` - 向结构体添加字段
- `POST /data_types/enum/add_value` - 向枚举添加值
- `POST /data_types/{path}/update` - 更新数据类型属性

### 删除操作
- `POST /data_types/{path}/delete` - 删除数据类型
- `POST /data_types/struct/remove_field` - 删除结构体字段
- `POST /data_types/enum/remove_value` - 删除枚举值

### 分类管理
- `GET /categories` - 列出所有分类
- `POST /categories` - 创建新分类
- `POST /categories/{path}/delete` - 删除分类
- `GET /categories/{path}/data_types` - 获取分类下的数据类型

## Resources

### 文件路径
- Java 源文件: `src/main/java/com/lauriewired/GhidraMCPPlugin.java`
- Python MCP 桥接: `bridge_mcp_ghidra.py`
- 项目文档: `CLAUDE.md`
- 规划目录: `.planning/`

### Ghidra API 参考
- DataTypeManager: 数据类型管理核心接口
- DataType: 所有数据类型的基接口
- Category/CategoryPath: 分类管理
- Structure/Union: 复合类型
- Enum: 枚举类型
- FunctionDefinition: 函数定义类型
- DataTypeComponent: 复合类型的字段/组件

### 现有代码参考位置
- `resolveDataType()`: 第 1442-1513 行
- `findDataTypeByNameInAllCategories()`: 第 1519-1548 行
- `setLocalVariableType()`: 第 1124-1263 行

### 分页实现模式
参考现有的 `/methods` 端点:
```java
List<Function> functions = new ArrayList<>();
Iterator<Function> iter = listing.getFunctions(true);
int count = 0;
int added = 0;
while (iter.hasNext() && added < limit) {
    Function f = iter.next();
    if (count >= offset) {
        functions.add(f);
        added++;
    }
    count++;
}
```

## Visual/Browser Findings
### 三个并行 Agents 研究结果一致性验证 ✅

**Agent 1 (ac383fe)**: DataTypeManager 基础 API
- 核心接口完整覆盖
- 查询、创建、删除方法齐全
- 分类管理 API 详细

**Agent 2 (af852bd)**: 数据类型修改操作
- 结构体字段操作详细
- 枚举值操作完整
- 事务处理示例丰富

**Agent 3 (a8bb5c1)**: 查询和过滤功能
- 搜索方法全面
- 分页实现建议
- 性能优化考虑

**交叉验证结果**: 所有 agents 的发现高度一致,没有矛盾或冲突。可以信任这些研究结果用于实现。

---
*基于 3 个并行 Explore agents 的研究成果创建*
*所有 API 信息经过交叉验证,可靠且完整*
