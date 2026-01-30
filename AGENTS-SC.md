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

## 下一步
- 实现 Phase 1：Job 状态机、持久化、workflow.* MCP 接口。
- 实现 Phase 2：unity_locate + il2cpp_dump（对接 Il2CppDumper）。
- 实现 Phase 3/4：IDA headless 分析 + 符号/伪代码导出。

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
