# 并行执行策略

## Sprint 并行度分析

### Sprint 1: 基础查询功能
**总任务**: 3
**最大并行度**: 1 → 2

```
Task 1.1 (独立) → [Task 1.2, Task 1.3 可并行]
```

**执行策略**:
1. **阶段 1**: 先执行 Task 1.1 (阻塞任务)
2. **阶段 2**: 并行执行 Task 1.2 和 Task 1.3

**Agents 分配**:
- 阶段 1: 1 个 agent 实现 Task 1.1
- 阶段 2: 2 个 agents 并行实现 Task 1.2 和 Task 1.3

---

### Sprint 2: 创建数据类型
**总任务**: 4
**最大并行度**: 3

```
[Task 2.1, Task 2.2, Task 2.4 可并行] → Task 2.3 (依赖 2.1)
```

**执行策略**:
1. **阶段 1**: 并行执行 Task 2.1 (结构体), Task 2.2 (枚举), Task 2.4 (Typedef)
2. **阶段 2**: 执行 Task 2.3 (联合体,依赖 2.1)

**Agents 分配**:
- 阶段 1: 3 个 agents 并行实现
  - Agent A: Task 2.1 - 创建结构体
  - Agent B: Task 2.2 - 创建枚举
  - Agent C: Task 2.4 - 创建 Typedef
- 阶段 2: 1 个 agent 实现 Task 2.3

**时间节省**: 串行需要 ~3.5 小时,并行只需 ~2 小时

---

### Sprint 3: 修改数据类型
**总任务**: 4
**最大并行度**: 2

```
Task 2.1 → [Task 3.1, Task 3.3 可并行]
Task 2.2 → [Task 3.2, Task 3.4 可并行]
```

**执行策略**:
1. **阶段 1**: 两个任务组并行执行
   - 组 1: Task 3.1 (添加字段) 和 Task 3.3 (删除字段)
   - 组 2: Task 3.2 (添加枚举值) 和 Task 3.4 (删除枚举值)

**Agents 分配**:
- 最多 2 个 agents (每组内串行)
  - Agent A: 先 Task 3.1 → Task 3.3
  - Agent B: 先 Task 3.2 → Task 3.4

---

### Sprint 4: 删除数据类型
**总任务**: 1
**最大并行度**: 1

单任务,无法并行。

---

### Sprint 5: 分类管理
**总任务**: 3
**最大并行度**: 1 → 2

```
[Task 5.1, Task 5.2 可并行] → Task 5.3 (依赖 5.1)
```

**执行策略**:
1. **阶段 1**: 并行执行 Task 5.1 和 Task 5.2
2. **阶段 2**: 执行 Task 5.3

---

### Sprint 6: 高级查询
**总任务**: 3
**最大并行度**: 3

```
Task 1.1 → [Task 6.1, Task 6.2, Task 6.3 可并行]
```

**执行策略**:
1. **阶段 1**: 等待 Task 1.1 完成
2. **阶段 2**: 并行执行所有 3 个任务

**Agents 分配**:
- 3 个 agents 并行实现
  - Agent A: Task 6.1 - 列出结构体
  - Agent B: Task 6.2 - 列出枚举
  - Agent C: Task 6.3 - 列出联合体

---

### Sprint 7: 端到端测试
**总任务**: 8
**最大并行度**: 1

**需要人工操作**,不适合并行 agents。

---

## 并行执行规则

### ✅ 可以并行的情况

1. **无依赖的任务** - 不同端点,无共享状态
   - 示例: Task 2.1, 2.2, 2.4

2. **相同依赖的不同任务** - 都依赖同一个已完成任务
   - 示例: Task 6.1, 6.2, 6.3 都依赖 Task 1.1

3. **功能独立的任务** - 不修改相同文件
   - 示例: 结构体操作 vs 枚举操作

### ⚠️ 需要串行的情况

1. **有直接依赖** - Task B 依赖 Task A
   - 示例: Task 2.3 依赖 Task 2.1

2. **修改同一文件** - 避免合并冲突
   - 示例: 多个 agent 同时修改 GhidraMCPPlugin.java

3. **共享状态** - 需要前一个任务创建的数据
   - 示例: 修改任务依赖创建任务

### 🚫 不适合并行的情况

1. **需要人工干预** - Sprint 7 的端到端测试
2. **需要硬件设备** - 真实设备测试
3. **需要 GUI 交互** - Ghidra 界面操作

---

## 实际执行建议

### 方案 A: 激进并行 (最快,但资源消耗大)
```python
Sprint 1: 1 → 2 agents
Sprint 2: 3 → 1 agents
Sprint 3: 2 agents (组内串行)
Sprint 4: 1 agent
Sprint 5: 2 → 1 agents
Sprint 6: 3 agents
Sprint 7: 人工操作
```

**优势**: 最快完成
**劣势**: 消耗更多 tokens,需要更多协调

### 方案 B: 适度并行 (推荐)
```python
Sprint 1: 1 → 2 agents
Sprint 2: 2 → 1 agents (Task 2.1 + 2.2 并行,2.4 串行)
Sprint 3: 2 agents
Sprint 4: 1 agent
Sprint 5: 2 → 1 agents
Sprint 6: 2 agents (Task 6.1 + 6.2 并行,6.3 串行)
Sprint 7: 人工操作
```

**优势**: 平衡速度和资源
**劣势**: 比方案 A 慢一点

### 方案 C: 保守并行 (最省资源)
```python
Sprint 1: 1 agent (全部串行)
Sprint 2: 2 agents (Task 2.1 + 2.2 并行)
Sprint 3: 1 agent (全部串行)
Sprint 4: 1 agent
Sprint 5: 1 agent
Sprint 6: 2 agents (Task 6.1 + 6.2 并行)
Sprint 7: 人工操作
```

**优势**: 最省 tokens
**劣势**: 最慢完成

---

## 协调和通信

### 并行 Agents 的职责划分

**Agent A (主 Agent)**:
- 协调其他 agents
- 处理共享资源冲突
- 合并代码更改
- 测试集成

**Agent B/C/D (工作 Agents)**:
- 专注实现分配的任务
- 报告进度和问题
- 不修改共享代码(除分配的部分)

### 避免冲突的策略

1. **文件级别隔离**
   - Agent A 修改 GhidraMCPPlugin.java 的行 100-500
   - Agent B 修改 GhidraMCPPlugin.java 的行 600-1000

2. **功能级别隔离**
   - Agent A 实现结构体相关端点
   - Agent B 实现枚举相关端点

3. **提交顺序**
   - 每个 agent 完成后先不提交
   - 等待所有并行 agents 完成
   - 主 agent 统一提交

---

## 执行命令模板

### 启动并行 Agents

```python
# Sprint 2, 阶段 1: 并行执行 3 个任务
agent_tasks = [
    {
        "agent": "general-purpose",
        "task": "Implement Task 2.1: Create Structure",
        "file": "GhidraMCPPlugin.java",
        "lines": "400-600"
    },
    {
        "agent": "general-purpose",
        "task": "Implement Task 2.2: Create Enum",
        "file": "GhidraMCPPlugin.java",
        "lines": "600-800"
    },
    {
        "agent": "general-purpose",
        "task": "Implement Task 2.4: Create Typedef",
        "file": "GhidraMCPPlugin.java",
        "lines": "800-1000"
    }
]

# 使用 Task tool 启动
for task_spec in agent_tasks:
    Task(subagent_type="general-purpose",
         description=task_spec["task"],
         prompt=f"{full_task_spec}")
```

---

## 推荐执行方案

### 🎯 推荐方案 B: 适度并行

**理由**:
1. 平衡速度和资源消耗
2. 减少协调复杂度
3. 降低合并冲突风险
4. 易于跟踪和调试

**具体计划**:
- Sprint 1: 先 Task 1.1 (1 agent),然后 1.2 + 1.3 并行 (2 agents)
- Sprint 2: 2.1 + 2.2 并行 (2 agents),然后 2.4 串行,最后 2.3
- Sprint 3: 2 个 agents 各自处理一组任务
- Sprint 4: 1 agent
- Sprint 5: 5.1 + 5.2 并行 (2 agents),然后 5.3
- Sprint 6: 6.1 + 6.2 并行 (2 agents),然后 6.3
- Sprint 7: 人工操作

**预估时间**:
- 方案 A: ~15 小时
- 方案 B: ~18 小时 ← 推荐
- 方案 C: ~25 小时

---

## 启动指令

当你准备开始时,告诉我:

```
开始执行方案 B,从 Sprint 1, Task 1.1 开始
```

我会:
1. 启动 1 个 agent 实现 Task 1.1
2. 完成后,启动 2 个 agents 并行实现 Task 1.2 和 1.3
3. 依次执行各个 Sprint
4. 每个完成后汇报进度

准备好了吗?
