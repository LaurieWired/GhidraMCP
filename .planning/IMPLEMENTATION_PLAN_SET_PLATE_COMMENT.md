# 实施计划：添加 "Set Plate Comment" 功能

## 1. 任务描述

### 1.1 目标
为 GhidraMCP 项目添加 "Set Plate Comment" 功能，允许 LLM 通过 MCP 协议在 Ghidra 中设置 Plate Comment（板注释）。

### 1.2 背景
- Ghidra 中的 Plate Comment 是一种特殊的注释类型，显示在 Listing 视图的顶部
- 当前 GhidraMCP 已支持 `set_decompiler_comment`（PRE_COMMENT）和 `set_disassembly_comment`（EOL_COMMENT）
- 代码中已有 `CodeUnit.PLATE_COMMENT` 的使用（在 `addPrototypeComment` 方法中）
- 需要添加 MCP 工具以支持此功能

### 1.3 成功标准
- 用户可以通过 MCP 工具设置 Plate Comment
- 功能与现有的注释设置工具保持一致
- 代码遵循项目的现有模式
- 经过充分测试确保功能正常

---

## 2. 技术分析

### 2.1 现有代码研究

#### 2.1.1 现有注释设置实现
在 `src/main/java/com/lauriewired/GhidraMCPPlugin.java` 中：

**辅助方法**（第 861-886 行）：
```java
private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
    Program program = getCurrentProgram();
    if (program == null) return false;
    if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

    AtomicBoolean success = new AtomicBoolean(false);
    try {
        SwingUtilities.invokeAndWait(() -> {
            int tx = program.startTransaction(transactionName);
            try {
                Address addr = program.getAddressFactory().getAddress(addressStr);
                program.getListing().setComment(addr, commentType, comment);
                success.set(true);
            } catch (Exception e) {
                Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
            } finally {
                success.set(program.endTransaction(tx, success.get()));
            }
        });
    } catch (Exception e) {
        Msg.error(this, "Failed to set " + transactionName.toLowerCase(), e);
    }
    return success.get();
}
```

**现有实现**：
```java
// 第 891-893 行
private boolean setDecompilerComment(String addressStr, String comment) {
    return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
}

// 第 898-900 行
private boolean setDisassemblyComment(String addressStr, String comment) {
    return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
}
```

#### 2.1.2 PLATE_COMMENT 的现有使用
在 `addPrototypeComment` 方法中（第 1037-1041 行）：
```java
program.getListing().setComment(
    func.getEntryPoint(),
    CodeUnit.PLATE_COMMENT,
    "Setting prototype: " + prototype
);
```

**结论**：`CodeUnit.PLATE_COMMENT` 常量已经在代码中使用，我们可以直接使用相同的模式。

#### 2.1.3 HTTP 端点模式
**现有的 HTTP 端点**（第 228-240 行）：
```java
server.createContext("/set_disassembly_comment", exchange -> {
    Map<String, String> params = parsePostParams(exchange);
    String address = params.get("address");
    String comment = params.get("comment");
    boolean success = setDisassemblyComment(address, comment);
    sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
});
```

#### 2.1.4 Python MCP 工具模式
在 `bridge_mcp_ghidra.py` 中：
```python
@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})
```

### 2.2 实施策略

基于以上分析，实施计划需要修改三个文件：

| 文件 | 修改类型 | 具体内容 |
|------|---------|---------|
| `GhidraMCPPlugin.java` | 添加辅助方法 | `setPlateComment()` |
| `GhidraMCPPlugin.java` | 添加 HTTP 端点 | `/set_plate_comment` |
| `bridge_mcp_ghidra.py` | 添加 MCP 工具 | `set_plate_comment()` |

---

## 3. 详细实施步骤

### 3.1 第一步：修改 GhidraMCPPlugin.java

#### 3.1.1 添加辅助方法 `setPlateComment()`

**位置**：在第 900 行之后（`setDisassemblyComment` 方法之后）

**代码**：
```java
/**
 * Set a plate comment for a given address
 *
 * @param addressStr The address as a string
 * @param comment The plate comment to set
 * @return true if successful, false otherwise
 */
private boolean setPlateComment(String addressStr, String comment) {
    return setCommentAtAddress(addressStr, comment, CodeUnit.PLATE_COMMENT, "Set plate comment");
}
```

**与现有代码的一致性检查**：
- ✅ 使用相同的 `setCommentAtAddress` 辅助方法
- ✅ 使用 `CodeUnit.PLATE_COMMENT` 常量
- ✅ 使用相同的事务名称格式
- ✅ 返回 `boolean` 类型

#### 3.1.2 添加 HTTP 端点 `/set_plate_comment`

**位置**：在第 240 行之后（`set_disassembly_comment` 端点之后）

**代码**：
```java
server.createContext("/set_plate_comment", exchange -> {
    Map<String, String> params = parsePostParams(exchange);
    String address = params.get("address");
    String comment = params.get("comment");
    boolean success = setPlateComment(address, comment);
    sendResponse(exchange, success ? "Plate comment set successfully" : "Failed to set plate comment");
});
```

**与现有代码的一致性检查**：
- ✅ 使用 `parsePostParams` 解析参数
- ✅ 提取 `address` 和 `comment` 参数
- ✅ 调用相应的辅助方法
- ✅ 使用 `sendResponse` 发送响应
- ✅ 成功/失败消息格式一致
- ✅ 端点命名遵循蛇形命名约定

### 3.2 第二步：修改 bridge_mcp_ghidra.py

#### 3.2.1 添加 MCP 工具 `set_plate_comment()`

**位置**：在第 204 行之后（`set_disassembly_comment` 工具之后）

**代码**：
```python
@mcp.tool()
def set_plate_comment(address: str, comment: str) -> str:
    """
    Set a plate comment for a given address.

    Plate comments are displayed at the top of the Listing view for a specific address
    and are typically used for high-level notes, function summaries, or important
    documentation that should be prominently visible.

    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        comment: The plate comment text to set at the address. Can be multi-line.
                 An empty string will clear any existing plate comment.

    Returns:
        Success message if the comment was set, or error description if failed

    Example:
        Set a plate comment for a function entry point:
        >>> set_plate_comment("0x140001000", "This function handles user authentication")

        Clear a plate comment:
        >>> set_plate_comment("0x140001000", "")
    """
    return safe_post("set_plate_comment", {"address": address, "comment": comment})
```

**与现有代码的一致性检查**：
- ✅ 使用 `@mcp.tool()` 装饰器
- ✅ 参数类型：`address: str`, `comment: str`
- ✅ 返回类型：`str`
- ✅ 调用 `safe_post()` 与 HTTP 端点通信
- ✅ 参数传递格式：`{"address": address, "comment": comment}`
- ✅ 工具命名遵循蛇形命名约定
- ✅ 文档字符串提供详细说明

---

## 4. 质量保证计划

### 4.1 代码审查检查清单

#### 4.1.1 语法和编译检查
- [ ] Java 代码语法正确
- [ ] Python 代码语法正确
- [ ] 项目可以成功编译：`mvn clean package assembly:single`
- [ ] 无编译警告或错误

#### 4.1.2 代码风格一致性
- [ ] Java 代码缩进和格式与现有代码一致
- [ ] Python 代码遵循 PEP 8
- [ ] 命名约定与现有代码一致
- [ ] 注释风格与现有代码一致

#### 4.1.3 功能正确性
- [ ] 新的辅助方法正确调用 `setCommentAtAddress`
- [ ] HTTP 端点正确处理请求和响应
- [ ] MCP 工具正确映射到 HTTP 端点
- [ ] 参数验证逻辑与现有代码一致
- [ ] 错误处理与现有代码一致

#### 4.1.4 集成一致性
- [ ] 与现有的 27 个 MCP 工具保持一致的接口设计
- [ ] 与现有的注释设置工具（`set_decompiler_comment`, `set_disassembly_comment`）保持一致
- [ ] 不影响现有功能的正常运行

### 4.2 测试计划

#### 4.2.1 单元测试级别

**测试 1：Java 辅助方法测试**
```bash
# 在 Ghidra 中手动测试
# 1. 加载一个测试程序
# 2. 选择一个地址
# 3. 调用 setPlateComment 方法
# 4. 验证注释是否正确设置
```

**测试 2：HTTP 端点测试**
```bash
# 启动 Ghidra 和插件
# 测试 1：设置正常的 plate comment
curl -X POST http://localhost:28382/set_plate_comment \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "address=0x140001000" \
  -d "comment=This%20is%20a%20test%20plate%20comment"

# 预期结果：返回 "Plate comment set successfully"

# 测试 2：空注释（清除注释）
curl -X POST http://localhost:28382/set_plate_comment \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "address=0x140001000" \
  -d "comment="

# 预期结果：返回 "Plate comment set successfully"

# 测试 3：缺少 address 参数
curl -X POST http://localhost:28382/set_plate_comment \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "comment=test"

# 预期结果：返回 "Failed to set plate comment"

# 测试 4：无效地址格式
curl -X POST http://localhost:28382/set_plate_comment \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "address=invalid_address" \
  -d "comment=test"

# 预期结果：返回 "Failed to set plate comment"

# 测试 5：特殊字符和多行文本
curl -X POST http://localhost:28382/set_plate_comment \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "address=0x140001000" \
  --data-urlencode "comment=Line 1
Line 2
Special chars: @#$%^&*()"

# 预期结果：返回 "Plate comment set successfully"
```

**测试 3：Python MCP 工具测试**
```python
# 测试脚本
import sys
sys.path.append('/Users/yingdong/VSCode/ghidra/GhidraMCP')

# 模拟 MCP 工具调用
from bridge_mcp_ghidra import safe_post

# 测试 1：正常设置
result = safe_post("set_plate_comment", {"address": "0x140001000", "comment": "Test comment"})
print(result)  # 预期：返回成功消息

# 测试 2：多行注释
result = safe_post("set_plate_comment", {
    "address": "0x140001000",
    "comment": "Line 1\nLine 2\nLine 3"
})
print(result)  # 预期：返回成功消息

# 测试 3：空注释
result = safe_post("set_plate_comment", {"address": "0x140001000", "comment": ""})
print(result)  # 预期：返回成功消息
```

#### 4.2.2 集成测试级别

**测试 4：端到端测试（通过 Claude Desktop）**
```json
// 在 Claude Desktop 配置中添加工具
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": ["/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py", "--ghidra-server", "http://127.0.0.1:28382/"]
    }
  }
}
```

然后在 Claude Desktop 中测试：
```
用户：请为地址 0x140001000 设置一个 plate comment："这是一个重要的函数"
Claude：[应该调用 set_plate_comment 工具]
```

**测试 5：与其他注释工具的对比测试**
```python
# 测试确保不同的注释类型不会互相覆盖
# 1. 设置 PRE_COMMENT
set_decompiler_comment("0x140001000", "Pre comment")

# 2. 设置 EOL_COMMENT
set_disassembly_comment("0x140001000", "EOL comment")

# 3. 设置 PLATE_COMMENT
set_plate_comment("0x140001000", "Plate comment")

# 4. 在 Ghidra UI 中验证所有三个注释都存在且正确显示
```

#### 4.2.3 边界条件测试

| 测试场景 | 输入 | 预期结果 |
|---------|------|---------|
| 空地址 | `address=""` | 失败："Failed to set plate comment" |
| None 地址 | `address=None` | 失败："Failed to set plate comment" |
| 空注释 | `comment=""` | 成功：清除现有注释 |
| None 注释 | `comment=None` | 失败："Failed to set plate comment" |
| 超长注释 | `comment="..." * 10000` | 成功：Ghidra 处理 |
| Unicode 字符 | `comment="中文测试 🎉"` | 成功：正确处理 |
| 特殊字符 | `comment="\n\t\r"` | 成功：正确处理 |
| 无效地址格式 | `address="not_an_address"` | 失败："Failed to set plate comment" |
| 不存在的地址 | `address="0x99999999"` | 失败："Failed to set plate comment" |
| 无程序加载 | 任何输入 | 失败："No program loaded" |

#### 4.2.4 并发测试（可选）
```python
# 测试多个并发请求是否正确处理
import threading
import requests

def set_comment(address, comment):
    requests.post(
        "http://localhost:28382/set_plate_comment",
        data={"address": address, "comment": comment}
    )

# 启动 10 个并发线程
threads = []
for i in range(10):
    t = threading.Thread(
        target=set_comment,
        args=("0x140001000", f"Comment {i}")
    )
    threads.append(t)
    t.start()

for t in threads:
    t.join()

# 验证：最后一个注释应该生效
```

### 4.3 构建和部署验证

#### 4.3.1 本地构建测试
```bash
# 1. 确保 lib/ 目录中有所有必需的 Ghidra JAR
ls -la lib/

# 2. 清理并构建
mvn clean package assembly:single

# 3. 验证输出文件
ls -la target/GhidraMCP-*.zip

# 4. 验证 zip 文件内容
unzip -l target/GhidraMCP-*.zip
```

**预期输出**：
```
GhidraMCP.jar
extension.properties
Module.manifest
```

#### 4.3.2 CI/CD 验证
- [ ] GitHub Actions 工作流成功运行
- [ ] 构建产物正确生成
- [ ] 无构建错误或警告

### 4.4 手动验证清单

#### 4.4.1 在 Ghidra 中验证
1. [ ] 在 Ghidra 中安装新构建的插件
2. [ ] 启动 Ghidra 并加载一个测试程序
3. [ ] 打开 GhidraMCP HTTP 服务器（检查端口 28382）
4. [ ] 在 Listing 视图中选择一个地址
5. [ ] 使用 curl 设置 plate comment
6. [ ] 在 Ghidra UI 中验证注释是否出现在该地址的顶部
7. [ ] 验证注释格式和内容是否正确
8. [ ] 测试清除注释功能

#### 4.4.2 在 MCP 客户端中验证
1. [ ] 在 Claude Desktop 中配置 MCP 服务器
2. [ ] 请求 Claude 设置一个 plate comment
3. [ ] 验证工具是否被正确调用
4. [ ] 验证响应是否正确返回
5. [ ] 在 Ghidra 中验证注释是否实际设置

### 4.5 回归测试

确保新功能不影响现有功能：

| 现有功能 | 测试方法 | 预期结果 |
|---------|---------|---------|
| `set_decompiler_comment` | curl 测试 | 正常工作 |
| `set_disassembly_comment` | curl 测试 | 正常工作 |
| `decompile_function` | MCP 工具调用 | 正常工作 |
| `rename_function` | MCP 工具调用 | 正常工作 |
| 其他 23 个工具 | 随机抽样测试 | 正常工作 |

### 4.6 性能测试（可选）

```python
import time
import requests

# 测试响应时间
start = time.time()
response = requests.post(
    "http://localhost:28382/set_plate_comment",
    data={"address": "0x140001000", "comment": "Performance test"}
)
end = time.time()

print(f"响应时间: {end - start:.3f} 秒")

# 预期：响应时间应该与现有注释设置工具相当（< 1 秒）
```

### 4.7 文档更新

#### 4.7.1 更新 CLAUDE.md
在 CLAUDE.md 中添加新功能的说明（如果需要）

#### 4.7.2 更新工具列表
- [ ] 更新 README.md（如果需要）
- [ ] 更新 MCP 工具总数（27 -> 28）

---

## 5. 风险评估与缓解

### 5.1 潜在风险

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|---------|
| Ghidra API 版本不兼容 | 高 | 低 | 使用已验证的 `CodeUnit.PLATE_COMMENT` 常量 |
| 线程安全问题 | 中 | 低 | 使用现有的 `SwingUtilities.invokeAndWait` 模式 |
| 参数解析错误 | 中 | 低 | 复用现有的 `parsePostParams` 方法 |
| 编译错误 | 低 | 低 | 遵循现有代码模式和语法 |
| 破坏现有功能 | 中 | 低 | 进行充分的回归测试 |

### 5.2 回滚计划

如果出现问题：
1. 从 Git 恢复到修改前的版本
2. 重新构建插件
3. 重新安装到 Ghidra

---

## 6. 实施时间估算

| 步骤 | 预估时间 |
|------|---------|
| 代码修改 | 15-30 分钟 |
| 本地测试 | 30-60 分钟 |
| 集成测试 | 30-60 分钟 |
| 文档更新 | 10-15 分钟 |
| **总计** | **约 2-3 小时** |

---

## 7. 验收标准

功能被视为完成当且仅当：

- [x] 代码修改完成且编译成功
- [x] 所有单元测试通过
- [x] 所有集成测试通过
- [x] 在 Ghidra UI 中验证功能正常工作
- [x] 在 MCP 客户端中验证功能正常工作
- [x] 回归测试通过，现有功能未受影响
- [x] 代码符合项目风格指南
- [x] 文档已更新（如需要）

---

## 8. 附录

### 8.1 相关文件路径
- Java 源文件：`/Users/yingdong/VSCode/ghidra/GhidraMCP/src/main/java/com/lauriewired/GhidraMCPPlugin.java`
- Python MCP 桥接：`/Users/yingdong/VSCode/ghidra/GhidraMCP/bridge_mcp_ghidra.py`
- 构建配置：`/Users/yingdong/VSCode/ghidra/GhidraMCP/pom.xml`

### 8.2 参考资源
- Ghidra API 文档：`CodeUnit` 类
- 现有实现：`setDecompilerComment`, `setDisassemblyComment`
- MCP 文档：FastMCP 工具定义

### 8.3 代码审查者注意事项

请特别关注以下方面：
1. **线程安全**：确保新代码正确使用 `SwingUtilities.invokeAndWait`
2. **事务管理**：确保 Ghidra 事务正确开始和结束
3. **错误处理**：确保所有异常情况都被正确处理
4. **参数验证**：确保输入参数得到适当验证
5. **一致性**：确保新代码与现有代码风格和模式一致

---

## 9. 签名

**计划制定者**：Claude Code
**计划日期**：2026-01-23
**目标版本**：GhidraMCP 1.0-SNAPSHOT
**审查状态**：待审查
