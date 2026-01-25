# 测试指南 - 结构体创建修复

## 修复时间
2026-01-24 21:52

## 问题描述
之前创建结构体时遇到错误："Paths must have non-empty elements"

## 修复方案
**根本原因**: Ghidra 的根路径 "/" 不能直接用于存放数据类型

**解决方案**: 当用户传入 `categoryPath: "/"` 时，自动使用 `/MyTypes` 作为默认分类

## 测试步骤

### 1. 重新安装插件

```bash
# 编译产物位置
target/GhidraMCP-1.0-SNAPSHOT.zip (40K)

# 安装方法 A - 手动复制（推荐）
unzip -o target/GhidraMCP-1.0-SNAPSHOT.zip -d /tmp/ghidra-extension/
cp -r /tmp/ghidra-extension/* ~/ghidra/.ghidra/12.0.1/Extensions/GhidraMCP/

# 安装方法 B - 使用 Ghidra 的扩展管理器
# File -> Install Extensions -> 导入 target/GhidraMCP-1.0-SNAPSHOT.zip
```

### 2. 启动 Ghidra 并加载程序

1. 启动 Ghidra
2. 打开任意程序（或创建新项目）
3. 确保 GhidraMCP HTTP 服务器已启动（Window -> GhidraMCP Server）
4. 记录服务器端口号（通常是 28382）

### 3. 测试用例

#### 测试用例 1: 使用根路径 "/" (应自动转换为 /MyTypes)

```bash
curl -X POST http://localhost:28382/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Point",
    "categoryPath": "/",
    "fields": [
      {"name": "x", "dataType": "/int", "length": 4},
      {"name": "y", "dataType": "/int", "length": 4}
    ]
  }'

# 预期结果:
# ✅ Structure 'Point' created successfully in category '/'
# ⚠️  实际创建位置: /MyTypes/Point
```

#### 测试用例 2: 使用自定义路径

```bash
curl -X POST http://localhost:28382/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Color",
    "categoryPath": "/Graphics",
    "fields": [
      {"name": "r", "dataType": "/uchar", "length": 1},
      {"name": "g", "dataType": "/uchar", "length": 1},
      {"name": "b", "dataType": "/uchar", "length": 1}
    ]
  }'

# 预期结果:
# ✅ Structure 'Color' created successfully in category '/Graphics'
```

#### 测试用例 3: 带描述和注释

```bash
curl -X POST http://localhost:28382/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Person",
    "categoryPath": "/MyTypes",
    "description": "人员信息结构体",
    "fields": [
      {"name": "id", "dataType": "/int", "length": 4, "comment": "人员ID"},
      {"name": "name", "dataType": "/char", "length": 32, "comment": "姓名"},
      {"name": "age", "dataType": "/int", "length": 4, "comment": "年龄"}
    ]
  }'

# 预期结果:
# ✅ Structure 'Person' created successfully in category '/MyTypes'
```

### 4. 验证结果

#### 方法 1: 通过 Ghidra GUI
1. 在 Ghidra 中打开 **Data Type Manager** (Window -> Data Type Manager)
2. 展开分类树
3. 检查新创建的结构体是否出现在正确的位置
4. 双击结构体查看字段定义

#### 方法 2: 通过 HTTP API 查询

```bash
# 列出所有数据类型
curl "http://localhost:28382/data_types?offset=0&limit=100"

# 获取特定结构体详情
curl "http://localhost:28382/data_types/MyTypes/Point"

# 搜索数据类型
curl "http://localhost:28382/data_types/search?name=Point&limit=10"
```

### 5. 检查调试输出

在 Ghidra 中打开 **Console** (Window -> Console)，应该能看到类似输出：

```
========== CREATE STRUCT START ==========
Received JSON: {"name":"Point","categoryPath":"/",...}
Parsed - name: 'Point', categoryPath: '/'
根路径 / 不支持，自动使用 /MyTypes
=== CategoryPath Debug ===
Input categoryPath: '/'
Actual catPath: '/MyTypes'
catPath.toString(): '/MyTypes'
catPath.getName(): 'MyTypes'
========================
Processing field: name=x, dataType=/int, length=4
Resolved field type: /int, category=/
Created structure: /MyTypes/Point
```

## 预期行为

### 成功指标
- ✅ HTTP 响应返回成功消息
- ✅ Ghidra Console 中有完整的调试输出
- ✅ 结构体出现在 Data Type Manager 中的正确位置
- ✅ 字段定义正确（名称、类型、长度、注释）

### 可能的问题

#### 问题 1: 405 Method Not Allowed
**原因**: HTTP 端点未正确注册
**解决**: 重启 Ghidra，重新安装插件

#### 问题 2: "Error: Data type '/int' not found"
**原因**: 字段类型路径不正确
**解决**: 确保使用 `/int` 而不是 `int`

#### 问题 3: "Error: Structure 'Point' already exists"
**原因**: 结构体名称冲突
**解决**: 使用不同的名称或先删除现有结构体

## 技术细节

### 修改的代码位置
`src/main/java/com/lauriewired/GhidraMCPPlugin.java` 第 2467-2484 行

### 核心逻辑
```java
// 创建类别路径
if (categoryPath.equals("/") || categoryPath.isEmpty()) {
    // 根路径不能直接使用，创建一个默认分类
    catPath = new CategoryPath("/MyTypes");
    Msg.info(this, "根路径 / 不支持，自动使用 /MyTypes");
} else {
    catPath = new CategoryPath(categoryPath);
}
```

### 为什么需要这个修复？

1. **Ghidra API 限制**: `CategoryPath.ROOT` 只能用于分类管理，不能直接存放数据类型
2. **空元素问题**: 根路径 "/" 的某些操作会产生空元素，违反 Ghidra API 要求
3. **用户体验**: 自动转换根路径为 "/MyTypes" 保持 API 的易用性

## 后续改进

1. **让用户指定默认分类**: 添加配置选项让用户自定义默认分类名称
2. **自动创建分类**: 如果指定分类不存在，自动创建
3. **支持删除分类**: 允许用户删除不再需要的分类
4. **分类管理 API**: 提供完整的分类 CRUD 操作

---

*测试指南生成于 2026-01-24 21:52*
*修复版本: target/GhidraMCP-1.0-SNAPSHOT.zip*
