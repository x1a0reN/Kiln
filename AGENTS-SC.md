# AGENTS

## 背景
- 目标：构建 Kiln，一个 Windows-only 的 MCP 服务器，用于编排游戏逆向工作流（优先 Unity IL2CPP）。
- 仓库：<repo-root>

## 目标架构
- 单一 stdio MCP 服务器（不依赖外部插件）。
- 内置工作流引擎 + 任务管理。
- 插件式模块：Unity IL2CPP、IDA headless、.NET 分析、打包。

## 项目结构
- Kiln.Mcp/Kiln.Mcp.csproj：MCP stdio 服务器（入口）。
- Kiln.Mcp/McpServer.cs：MCP JSON-RPC（initialize/tools/resources）+ 工具分发。
- Kiln.Mcp/ToolCatalog.cs：工具定义与输入 schema。
- Kiln.Mcp/ResourceCatalog.cs：内置资源（BepInEx 文档）+ resources/list/read。
- Kiln.Core/Kiln.Core.csproj：工作流 + 任务模型（核心）。
- Kiln.Plugins/Unity.Il2Cpp：Unity IL2CPP 管线模块（规划中）。
- Kiln.Plugins/Ida.Pro：IDA headless 自动化模块（规划中）。
- Kiln.Plugins/DotNetAnalysis：.NET 分析模块（规划中）。
- Kiln.Plugins/Packaging：打包与清单模块（规划中）。
- Kiln.slnx：包含所有 Kiln 项目的解决方案。

## 决策
- v0.1 仅支持 Windows。
- 先做 stdio MCP，后续再扩展 streamable HTTP。
- 先完成 Unity IL2CPP 纵向闭环，再扩展多引擎。

## 当前进度
- 2026-01-29：创建 AGENTS.md。
- 2026-01-29：新增 dnSpyEx MCP 插件 + bridge（历史阶段）。
- 2026-01-30：新增 MCP 资源支持（resources/list/read），内置 BepInEx 文档。
- 2026-01-30：新增 Kiln v0.1 计划与任务清单（PLAN.md、TASK.md）。
- 2026-01-30：Phase 0 启动——更名为 Kiln、移除 dnSpyEx 插件、建立 Kiln.Mcp/Kiln.Core/Kiln.Plugins 结构、重写 README 与工具列表、添加 kiln.config.template.json 并更新 .gitignore。
- 2026-01-30：Phase 1 完成——新增 KilnConfig 加载、JobManager（job.json 持久化 + 日志）、实现 workflow.run/status/logs/cancel MCP 处理（工作流暂为 stub）。
- 2026-01-30：Phase 2 完成——新增 Unity IL2CPP 定位与 Il2CppDumper 调用，接入 detect_engine/unity_locate/il2cpp_dump MCP 接口（支持配置默认 dumper 路径）。
- 2026-01-30：Phase 2 已验证——仓库清理完成且 Release 构建通过。
- 2026-01-30：Phase 2 加固——安全枚举 Unity 文件路径与异步读取 Il2CppDumper 输出。
- 2026-01-30：Phase 2 安全——限制 il2cpp_dump 仅使用配置的 Il2CppDumper 可执行文件。
- 2026-01-30：Phase 3 启动——ida_analyze 后台任务 + IDA headless 执行，产出 idb/log，并支持脚本钩子。

## 下一步
- 实现 Phase 3：IDA headless 分析 + 符号/类型加载。
- 实现 Phase 4：符号与伪代码导出。
- 实现 Phase 5：patch/codegen + 打包产物。

## 构建与运行

### 前置
- .NET SDK 10.x

### 构建
```
dotnet build Kiln.slnx -c Release
```

### 运行（stdio MCP）
```
dotnet run --project Kiln.Mcp -c Release
```

## 备注
- 每次更新都要在 AGENTS.md 记录进度。
- 仅支持 .NET 10 构建。
- 本地配置文件（不入库）：kiln.config.json

## 规则
- 每次修改后确认构建无错误，再提交并推送。
- 每次代码变更后更新 AGENTS.md 的进度。
- AGENTS.md 变更需同步更新 AGENTS-SC.md（规则块本身除外）。
- 新增 MCP 工具时需要更新 kiln.exampleFlow 的示例与用法。
- 所有改动在功能分支完成；PR 由用户发起并由用户最终合并。
