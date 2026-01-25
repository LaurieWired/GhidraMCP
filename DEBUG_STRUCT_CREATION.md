# 结构体创建调试指南

## 编译完成 ✅
- **编译时间**: 21:05
- **文件**: `target/GhidraMCP-1.0-SNAPSHOT.zip`
- **调试输出**: 已添加大量 System.out.println 和 Msg.info 调用

## 安装步骤

1. **重新安装插件**
   - 打开 Ghidra
   - `File` → `Install Extensions...`
   - 如果之前的 GhidraMCP 已安装，先选中它并点击 "Remove"
   - 重启 Ghidra
   - 再次 `File` → `Install Extensions...`
   - 点击齿轮图标 → `Install from File...`
   - 选择 `target/GhidraMCP-1.0-SNAPSHOT.zip`
   - 重启 Ghidra

2. **打开 Ghidra Console**
   - `Window` → `Console`
   - **重要**: 确保 Console 标签页可见

3. **测试命令**

### 测试 1: 根路径 "/"
```bash
curl -X POST http://localhost:28382/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{"name":"Point","categoryPath":"/","fields":[{"name":"x","dataType":"/int","length":4}]}'
```

### 测试 2: 子路径 "/engine"
```bash
curl -X POST http://localhost:28382/data_types/struct \
  -H "Content-Type: application/json" \
  -d '{"name":"EngineInfo","categoryPath":"/engine","fields":[{"name":"rpm","dataType":"/int","length":4}]}'
```

## 预期的调试输出

在 Console 中，你应该看到类似以下的输出（按顺序）：

```
========== HTTP: /data_types/struct called ==========
HTTP: Received body: {"name":"Point","categoryPath":"/","fields":[{"name":"x","dataType":"/int","length":4}]}
HTTP: Calling createStructFromJson...
========== METHOD: createStructFromJson called ==========
METHOD: Received JSON: {"name":"Point","categoryPath":"/","fields":[{"name":"x","dataType":"/int","length":4}]}
METHOD: Program loaded: [程序名称]
Parsed - name: 'Point', categoryPath: '/'
Extracted fields string: [{"name":"x","dataType":"/int","length":4}]
Category path created: '/'
Processing field: name=x, dataType=/int, length=4
Resolved field type: /int, category=/
```

## 可能的输出场景

### 场景 A: HTTP 端点没有被调用
如果 **没有任何输出**，说明：
- [ ] 端口不是 28382
- [ ] 服务器没有启动
- [ ] 路由没有正确注册

**检查方法**:
```bash
curl http://localhost:28382/methods
```
应该返回函数列表。

### 场景 B: HTTP 被调用，但方法没有被调用
如果只看到 `========== HTTP:` 开头的输出，但没有 `========== METHOD:` 输出，说明：
- [ ] `createStructFromJson()` 方法抛出异常
- [ ] 程序为 null（没有打开任何程序）

### 场景 C: 方法被调用，但在 CategoryPath 创建时失败
如果在 "Category path created:" 之前就失败了，说明问题在 CategoryPath 构造函数。

### 场景 D: 方法被调用，但在字段解析时失败
如果在 "Processing field:" 之前就失败了，说明问题在 `resolveDataType()` 或字段解析。

## 请报告以下信息

1. **Console 的完整输出**（复制所有文本）
2. **curl 返回的错误消息**（如果有）
3. **是否在 Console 中看到任何输出**（是/否）

## 下一步

根据 Console 输出，我们可以确定：
- 错误发生在哪个阶段
- 是 HTTP 层面的问题还是业务逻辑层面的问题
- 是 JSON 解析的问题还是 Ghidra API 调用的问题
