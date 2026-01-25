# Task 2.2: 创建枚举数据类型实现计划

## 功能概述
实现 POST /data_types/enum 端点,用于在 Ghidra 中创建枚举数据类型。

## 技术要求

### 1. HTTP 端点实现
- **路径**: POST /data_types/enum
- **Content-Type**: application/json
- **请求体**: JSON 格式的枚举定义

### 2. 请求格式
```json
{
  "name": "Color",
  "categoryPath": "/MyTypes",
  "size": 4,
  "description": "Color enumeration",
  "values": [
    {
      "name": "RED",
      "value": 0,
      "comment": "Red color"
    }
  ]
}
```

### 3. 验证规则
- **必需字段**: name, categoryPath, size
- **size 限制**: 必须是 1, 2, 4, 或 8 字节
- **枚举值**: 至少包含一个值
- **名称冲突**: 检查枚举名称是否已存在
- **枚举值名称**: 检查是否有重复的枚举值名称

### 4. 错误处理
- 无效的 size 值
- 名称冲突
- 枚举值名称重复
- 无效的 JSON 格式
- 事务失败

### 5. 实现步骤

#### 步骤 1: 添加 JSON 解析方法
- 创建 `parseJsonBody()` 方法解析 JSON 请求体
- 验证必需字段

#### 步骤 2: 实现 createEnum() 方法
- 使用 EnumDataType 构造函数创建枚举
- 使用 add() 方法添加枚举值
- 使用 DataTypeManager.addDataType() 添加到数据类型管理器

#### 步骤 3: 添加 HTTP 端点
- 注册 /data_types/enum 路径
- 处理 POST 请求
- 返回成功或错误消息

#### 步骤 4: 实现 MCP 工具
- 在 bridge_mcp_ghidra.py 中添加 create_enum() 工具
- 使用 requests.post() 发送 JSON 数据

## 依赖的 Ghidra API
- `ghidra.program.model.data.EnumDataType`
- `ghidra.program.model.data.DataTypeManager`
- `ghidra.program.model.data.CategoryPath`

## 测试计划

### 测试用例 1: 简单枚举
```bash
curl -X POST http://127.0.0.1:8080/data_types/enum \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Color",
    "categoryPath": "/MyTypes",
    "size": 4,
    "values": [
      {"name": "RED", "value": 0},
      {"name": "GREEN", "value": 1},
      {"name": "BLUE", "value": 2}
    ]
  }'
```

### 测试用例 2: 带注释的枚举
```bash
curl -X POST http://127.0.0.1:8080/data_types/enum \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Priority",
    "categoryPath": "/System",
    "size": 4,
    "description": "Task priority levels",
    "values": [
      {"name": "LOW", "value": 0, "comment": "Low priority"},
      {"name": "MEDIUM", "value": 1, "comment": "Medium priority"},
      {"name": "HIGH", "value": 2, "comment": "High priority"}
    ]
  }'
```

### 测试用例 3: 错误处理
- 无效的 size (size=3)
- 枚举值名称重复
- 名称冲突
- 无效的 JSON

## 预期输出
成功: "Enum created successfully"
失败: 详细的错误消息

## 实现时间估计
45 分钟
