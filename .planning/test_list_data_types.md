# 测试清单:列出所有数据类型 (GET /data_types)

## 功能概述
测试 `/data_types` HTTP 端点和 `list_data_types` MCP 工具的功能完整性。

## 实现的文件
1. **Java HTTP 端点**: `/Users/yingdong/VSCode/ghidra/GhidraMCP/src/main/java/com/lauriewired/GhidraMCPPlugin.java`
   - 新增 HTTP 端点: `/data_types` (第 352-357 行)
   - 新增辅助方法: `getAllDataTypePaths(int offset, int limit)` (第 409-435 行)

2. **Python MCP 工具**: `/Users/yingdong/VSCode/ghidra/GhidraMCP/bridge_mcp_ghidra.py`
   - 新增 MCP 工具: `list_data_types(offset, limit)` (第 333-353 行)

## 测试用例

### 测试用例 1: 基本功能测试 - 获取前 100 个数据类型

**测试目的**: 验证端点能正确返回数据类型列表

**前提条件**:
- Ghidra 已加载一个程序 (任何程序都可以)
- GhidraMCP 插件已启动并监听 8080 端口

**测试命令**:
```bash
curl "http://127.0.0.1:8080/data_types?offset=0&limit=10"
```

**预期输出**:
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

**通过标准**:
- HTTP 状态码为 200
- 返回纯文本,每行一个数据类型路径
- 包含基本数据类型如 `/byte`, `/int` 等
- 数据类型路径以 `/` 开头

---

### 测试用例 2: 分页测试 - offset 和 limit 参数

**测试目的**: 验证分页功能正常工作

**测试命令**:
```bash
# 第一页: 获取前 5 个数据类型
curl "http://127.0.0.1:8080/data_types?offset=0&limit=5"

# 第二页: 获取接下来的 5 个数据类型
curl "http://127.0.0.1:8080/data_types?offset=5&limit=5"
```

**预期输出**:
- 第一次请求返回前 5 个数据类型
- 第二次请求返回第 6-10 个数据类型
- 两次请求的结果不应重复

**通过标准**:
- 分页正确工作
- offset 和 limit 参数被正确解析
- 返回的数据类型数量不超过 limit

---

### 测试用例 3: 边界情况测试 - 超出范围的 offset

**测试目的**: 验证当 offset 超出数据总数时的处理

**测试命令**:
```bash
curl "http://127.0.0.1:8080/data_types?offset=999999&limit=100"
```

**预期输出**:
```
(空响应或 "No items in range")
```

**通过标准**:
- 返回空内容或适当的错误消息
- 不抛出异常
- HTTP 状态码为 200

---

### 测试用例 4: 默认参数测试

**测试目的**: 验证不传递参数时使用默认值

**测试命令**:
```bash
curl "http://127.0.0.1:8080/data_types"
```

**预期行为**:
- 使用默认 offset=0
- 使用默认 limit=100
- 返回前 100 个数据类型

**通过标准**:
- 返回数据类型列表
- 数量不超过 100 个
- HTTP 状态码为 200

---

### 测试用例 5: 无效参数测试

**测试目的**: 验证对无效参数的处理

**测试命令**:
```bash
# 无效的 offset (非数字)
curl "http://127.0.0.1:8080/data_types?offset=abc&limit=10"

# 无效的 limit (负数)
curl "http://127.0.0.1:8080/data_types?offset=0&limit=-5"
```

**预期行为**:
- 无效参数被忽略或使用默认值
- 不导致服务器崩溃
- 返回有效响应

**通过标准**:
- 服务器正常响应
- HTTP 状态码为 200
- 返回有效的数据类型列表

---

### 测试用例 6: Python MCP 工具测试

**测试目的**: 验证 Python MCP 工具正确调用 HTTP 端点

**测试脚本**:
```python
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/Users/yingdong/VSCode/ghidra/GhidraMCP')

# 测试 safe_get 函数
from bridge_mcp_ghidra import safe_get

# 设置服务器 URL
import bridge_mcp_ghidra
bridge_mcp_ghidra.ghidra_server_url = "http://127.0.0.1:8080/"

# 调用 list_data_types (使用 safe_get)
result = safe_get("data_types", {"offset": 0, "limit": 10})
print("返回的数据类型数量:", len(result))
print("前 10 个数据类型:")
for dt in result[:10]:
    print(" ", dt)
```

**预期输出**:
```
返回的数据类型数量: 10
前 10 个数据类型:
  /byte
  /char
  /double
  ...
```

**通过标准**:
- 返回列表格式
- 包含预期的数据类型路径
- 无错误或异常

---

### 测试用例 7: 数据类型路径格式验证

**测试目的**: 验证返回的数据类型路径格式正确

**测试命令**:
```bash
curl -s "http://127.0.0.1:8080/data_types?offset=0&limit=20" | head -20
```

**验证要点**:
- 所有路径以 `/` 开头
- 路径使用 `/` 作为分隔符
- 基本类型在根级别: `/int`, `/char` 等
- 复杂类型在命名空间下: `/windows/BYTE`, `/std/string` 等 (如果有)

**通过标准**:
- 路径格式统一
- 无空路径或 None 值
- 路径按字母顺序排序

---

### 测试用例 8: 性能测试 - 大量数据类型

**测试目的**: 验证在大量数据类型情况下的性能

**测试命令**:
```bash
time curl "http://127.0.0.1:8080/data_types?offset=0&limit=1000"
```

**预期行为**:
- 响应时间合理 (< 5 秒)
- 不出现内存溢出或性能问题
- 返回完整的数据类型列表

**通过标准**:
- 响应时间可接受
- 无错误或超时

---

## 测试结果记录

### 执行日期: _______________

| 测试用例 | 状态 | 备注 |
|---------|------|------|
| 测试用例 1: 基本功能测试 | ☐ 通过 ☐ 失败 | |
| 测试用例 2: 分页测试 | ☐ 通过 ☐ 失败 | |
| 测试用例 3: 边界情况测试 | ☐ 通过 ☐ 失败 | |
| 测试用例 4: 默认参数测试 | ☐ 通过 ☐ 失败 | |
| 测试用例 5: 无效参数测试 | ☐ 通过 ☐ 失败 | |
| 测试用例 6: Python MCP 工具测试 | ☐ 通过 ☐ 失败 | |
| 测试用例 7: 路径格式验证 | ☐ 通过 ☐ 失败 | |
| 测试用例 8: 性能测试 | ☐ 通过 ☐ 失败 | |

---

## 快速测试脚本

完整的测试脚本可以快速执行所有测试:

```bash
#!/bin/bash
# test_data_types.sh

BASE_URL="http://127.0.0.1:8080"

echo "=== 测试用例 1: 基本功能测试 ==="
curl -s "$BASE_URL/data_types?offset=0&limit=10"
echo -e "\n"

echo "=== 测试用例 2: 分页测试 ==="
echo "第一页 (offset=0, limit=5):"
curl -s "$BASE_URL/data_types?offset=0&limit=5"
echo -e "\n第二页 (offset=5, limit=5):"
curl -s "$BASE_URL/data_types?offset=5&limit=5"
echo -e "\n"

echo "=== 测试用例 3: 边界情况测试 ==="
curl -s "$BASE_URL/data_types?offset=999999&limit=100"
echo -e "(应为空)\n"

echo "=== 测试用例 4: 默认参数测试 ==="
curl -s "$BASE_URL/data_types" | wc -l
echo "(应返回不超过 100 行)\n"

echo "=== 测试用例 7: 路径格式验证 ==="
curl -s "$BASE_URL/data_types?offset=0&limit=20" | head -20
```

---

## 已知问题和解决方案

### 问题 1: 无程序加载时返回 "No program loaded"
**解决方案**: 在 Ghidra 中加载一个程序后再测试

### 问题 2: 某些内置类型可能不可见
**原因**: Ghidra 的数据类型管理器可能不包含所有内置类型
**解决方案**: 这是正常行为,不同程序可能有不同的数据类型集

---

## 代码审查要点

- ✅ 遵循现有代码风格和模式
- ✅ 使用 `paginateList()` 进行分页
- ✅ 使用 `parseQueryParams()` 解析查询参数
- ✅ 使用 `sendResponse()` 发送响应
- ✅ 添加了中文注释
- ✅ Python 工具使用 `@mcp.tool()` 装饰器
- ✅ Python 工具使用 `safe_get()` 调用端点
- ✅ 错误处理完善 (检查 program 和 dtm 是否为 null)

---

## 后续改进建议

1. **可选过滤参数**: 可以添加 `filter` 参数来按名称过滤数据类型
2. **分类显示**: 可以按类别分组返回数据类型
3. **详细信息**: 可以创建另一个端点返回单个数据类型的详细信息
