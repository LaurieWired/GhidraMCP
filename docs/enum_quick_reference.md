# 枚举创建快速参考

## 一分钟快速开始

### 1. 使用 curl 创建简单枚举

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

### 2. 使用 MCP 工具创建枚举

```python
create_enum(
    name="Color",
    category_path="/MyTypes",
    size=4,
    values=[
        {"name": "RED", "value": 0},
        {"name": "GREEN", "value": 1},
        {"name": "BLUE", "value": 2}
    ]
)
```

## 常用枚举模板

### 1字节状态枚举
```json
{
  "name": "Status",
  "categoryPath": "/",
  "size": 1,
  "values": [
    {"name": "OK", "value": 0},
    {"name": "ERROR", "value": 1},
    {"name": "PENDING", "value": 2}
  ]
}
```

### 4字节错误码枚举
```json
{
  "name": "ErrorCode",
  "categoryPath": "/System",
  "size": 4,
  "description": "系统错误码定义",
  "values": [
    {"name": "SUCCESS", "value": 0, "comment": "成功"},
    {"name": "INVALID_PARAM", "value": 100, "comment": "无效参数"},
    {"name": "OUT_OF_MEMORY", "value": 200, "comment": "内存不足"}
  ]
}
```

### Windows 消息类型枚举
```json
{
  "name": "WindowsMessage",
  "categoryPath": "/Windows",
  "size": 4,
  "description": "Windows 消息类型",
  "values": [
    {"name": "WM_NULL", "value": 0, "comment": "空消息"},
    {"name": "WM_CREATE", "value": 1, "comment": "创建窗口"},
    {"name": "WM_DESTROY", "value": 2, "comment": "销毁窗口"},
    {"name": "WM_PAINT", "value": 15, "comment": "绘制窗口"}
  ]
}
```

## size 参数选择指南

| size | 适用场景 | 值范围 | 示例 |
|------|----------|--------|------|
| 1 | 小范围枚举 | 0-255 | 状态码、标志位 |
| 2 | 中等范围枚举 | 0-65535 | 错误码、类型ID |
| 4 | 大多数情况 | 0-4294967295 | Windows消息、HTTP状态码 |
| 8 | 超大范围 | 0-2^63-1 | 指针、大整数ID |

## 错误处理速查

| 错误消息 | 原因 | 快速修复 |
|----------|------|----------|
| `'name' field is required` | 缺少名称 | 添加 `"name": "XXX"` |
| `'size' must be 1, 2, 4, or 8` | size 值无效 | 改为 1, 2, 4, 或 8 |
| `Duplicate enum value name` | 枚举值名称重复 | 修改枚举值名称 |
| `already exists` | 枚举已存在 | 使用不同名称或路径 |
| `at least one enum value` | values 为空 | 添加至少一个枚举值 |

## 验证命令

### 检查枚举是否创建成功
```bash
curl "http://127.0.0.1:8080/data_types/MyTypes/Color"
```

### 搜索枚举
```bash
curl "http://127.0.0.1:8080/data_types/search?name=Color&limit=10"
```

### 列出所有类型
```bash
curl "http://127.0.0.1:8080/data_types?offset=0&limit=100"
```

## 实用技巧

### 1. 使用描述和注释
```json
{
  "name": "Priority",
  "categoryPath": "/System",
  "size": 4,
  "description": "任务优先级 - 数字越大优先级越高",
  "values": [
    {"name": "LOW", "value": 0, "comment": "低优先级 - 后台任务"},
    {"name": "MEDIUM", "value": 1, "comment": "中优先级 - 普通任务"},
    {"name": "HIGH", "value": 2, "comment": "高优先级 - 重要任务"},
    {"name": "URGENT", "value": 3, "comment": "紧急 - 立即处理"}
  ]
}
```

### 2. 为枚举值创建别名
```json
{
  "name": "FilePermission",
  "categoryPath": "/System",
  "size": 4,
  "values": [
    {"name": "NONE", "value": 0},
    {"name": "READ", "value": 1},
    {"name": "WRITE", "value": 2},
    {"name": "EXECUTE", "value": 4},
    {"name": "ALL", "value": 7},
    {"name": "RW", "value": 3, "comment": "READ + WRITE"},
    {"name": "RX", "value": 5, "comment": "READ + EXECUTE"}
  ]
}
```

### 3. 组织枚举到不同的类别
```json
// 系统级枚举
{
  "name": "SystemError",
  "categoryPath": "/System/Errors",
  "size": 4,
  "values": [...]
}

// 应用级枚举
{
  "name": "AppError",
  "categoryPath": "/Application/Errors",
  "size": 4,
  "values": [...]
}

// 第三方库枚举
{
  "name": "LibError",
  "categoryPath": "/Libraries/MyLib",
  "size": 4,
  "values": [...]
}
```

## 测试命令

### 运行完整测试
```bash
cd /Users/yingdong/VSCode/ghidra/GhidraMCP/tests
./test_enum_creation.sh
```

### 快速单个测试
```bash
# 测试简单枚举
curl -X POST http://127.0.0.1:8080/data_types/enum \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","categoryPath":"/","size":4,"values":[{"name":"A","value":0}]}'
```

## 常见问题 FAQ

**Q: 可以创建位标志枚举吗?**
A: 可以,但需要手动设置值为 2 的幂次方:
```json
{
  "name": "Flags",
  "categoryPath": "/",
  "size": 4,
  "values": [
    {"name": "FLAG_1", "value": 1},
    {"name": "FLAG_2", "value": 2},
    {"name": "FLAG_3", "value": 4},
    {"name": "FLAG_4", "value": 8}
  ]
}
```

**Q: 枚举值可以是负数吗?**
A: 当前实现支持负数,但需要通过直接修改代码支持。

**Q: 如何修改已存在的枚举?**
A: 当前不支持修改,需要删除后重新创建(或使用 Ghidra GUI)。

**Q: 可以创建枚举数组吗?**
A: 枚举数组需要在结构体中使用枚举类型作为字段类型。

## 相关链接

- 完整API文档: [enum_creation_api.md](./enum_creation_api.md)
- 实现报告: [.planning/task_2_2_completion_report.md](../.planning/task_2_2_completion_report.md)
- 测试脚本: [tests/test_enum_creation.sh](../tests/test_enum_creation.sh)
