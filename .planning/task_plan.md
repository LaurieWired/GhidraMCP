# Task Plan: 实现数据类型处理功能
<!--
  WHAT: 为 GhidraMCP 添加完整的数据类型管理功能
  WHY: 当前 MCP 服务器仅支持有限的类型操作,需要添加完整的数据类型 CRUD 能力
  WHEN: 创建于 2026-01-24,数据类型 API 研究完成后
-->

## Goal
为 GhidraMCP 添加完整的数据类型处理功能,包括创建、查询、修改和删除数据类型(结构体、枚举、联合体、typedef、函数定义等),以及分类管理和高级查询功能。

## Current Phase
Phase 2: 设计 HTTP API 端点

## Phases

### Phase 1: 研究 Ghidra 数据类型 API ✅
- [x] 通过 3 个并行 Explore agents 研究 DataTypeManager API
- [x] 研究数据类型创建和修改 API
- [x] 研究数据类型查询和过滤 API
- [x] 验证研究结果的一致性
- [x] 文档化所有发现的 API 和方法
- **Status:** complete
- **完成时间:** 2026-01-24
- **Agents:**
  - ac383fe: DataTypeManager 基础 API
  - af852bd: 数据类型修改操作
  - a8bb5c1: 查询和过滤功能

### Phase 2: 设计 HTTP API 端点 🔄
- [x] 分析 GhidraMCP 现有的 API 设计模式
- [ ] 设计所有数据类型相关的 HTTP 端点
- [ ] 定义端点的参数格式和返回值
- [ ] 设计错误处理和响应格式
- [ ] 与用户确认 API 设计
- **Status:** in_progress

### Phase 3: 实现 Java 端点
- [ ] 在 GhidraMCPPlugin.java 中实现所有 HTTP 端点
- [ ] 实现数据类型查询端点
- [ ] 实现数据类型创建端点
- [ ] 实现数据类型修改端点
- [ ] 实现数据类型删除端点
- [ ] 实现分类管理端点
- [ ] 使用事务和线程安全模式
- **Status:** pending

### Phase 4: 实现 MCP 工具
- [ ] 在 bridge_mcp_ghidra.py 中为每个 HTTP 端点创建 MCP 工具
- [ ] 编写清晰的工具文档说明
- [ ] 实现参数验证和错误处理
- [ ] 使用 safe_get() 和 safe_post() 方法
- **Status:** pending

### Phase 5: 测试功能
- [ ] 单元测试每个 HTTP 端点
- [ ] 通过 MCP 客户端测试所有工具
- [ ] 测试边界情况和错误处理
- [ ] 验证事务正确性
- [ ] 性能测试(大数据集)
- **Status:** pending

### Phase 6: 文档和交付
- [ ] 更新 CLAUDE.md 文档
- [ ] 添加使用示例
- [ ] 更新 README(如需要)
- [ ] 提交代码并创建 PR
- **Status:** pending

## Key Questions
1. **端点命名约定**: 是否遵循 RESTful 风格(使用 PUT/DELETE)还是保持现有模式(所有修改都用 POST)?
   - **决定**: 保持现有模式,所有修改操作使用 POST,与现有 API 一致

2. **分页实现**: 在 Java 端实现分页还是返回全部数据在 Python 端分页?
   - **决定**: 在 Java 端实现 offset/limit 分页,提高性能

3. **数据类型路径格式**: 使用字符串路径("/Category/Type")还是 JSON 对象?
   - **决定**: 使用字符串路径,简洁且与 Ghidra API 一致

4. **冲突处理策略**: 创建数据类型时如何处理名称冲突?
   - **决定**: 使用 DataTypeConflictHandler.DEFAULT_HANDLER,提供选项让用户指定策略

5. **是否需要批量操作**: 是否支持批量创建/删除数据类型?
   - **决定**: 第一版先实现单个操作,后续可添加批量操作

## Decisions Made
| Decision | Rationale |
|----------|-----------|
| 保持现有 API 设计模式 | 所有修改操作使用 POST,与现有 `/set_*` 端点一致 |
| 在 Java 端实现分页 | 减少数据传输,提高大数据集性能 |
| 使用字符串路径表示数据类型 | 与 Ghidra API 一致,简洁易用 |
| 支持多种查询维度 | 按类型、分类、名称、大小等多维度过滤 |
| 优先实现核心功能 | 第一版实现常用操作,高级功能后续迭代 |

## Errors Encountered
| Error | Attempt | Resolution |
|-------|---------|------------|
| | 1 | |

## Notes
- **研究验证**: 三个并行 agents 的研究结果高度一致,API 信息可靠
- **现有模式**: 参考 GhidraMCPPlugin.java 中现有的 `resolveDataType()` 和 `findDataTypeByNameInAllCategories()` 方法
- **事务处理**: 所有修改操作必须使用 `program.startTransaction()` 和 `SwingUtilities.invokeAndWait()`
- **线程安全**: 遵循现有的线程安全模式
- **测试策略**: 先用 curl 测试 HTTP 端点,再通过 MCP 客户端测试完整流程
- **分支**: 当前在 `feature/data-type-handling` 分支开发
- **研究文档**: 详细的研究结果记录在 findings.md 中
