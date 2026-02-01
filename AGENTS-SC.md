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
- 2026-01-30：Phase 3 符号——IDA 分析完成后自动加载 Il2CppDumper 符号/类型（包装脚本）。
- 2026-01-30：Phase 3 配置——发布目录友好默认值与相对路径解析（dump/ida 输出）。
- 2026-01-30：Phase 3 修复——IDA -S 参数引用处理 + dump 目录一致性校验。
- 2026-01-30：Phase 3 配置——合并 Il2CppDumper 相关路径为 il2cppRootDir，并按游戏名创建 dump 子目录。
- 2026-01-30：Phase 4 导出——ida_export_symbols / ida_export_pseudocode 输出 JSON 产物。
- 2026-01-30：Phase 4 分析——新增 analysis.* 工具用于索引/检索符号与伪代码。
- 2026-01-30：Phase 5 完成——patch_codegen 模板 + package_mod 打包/清单/回滚产物。
- 2026-01-30：Phase 5 修复——打包 zip 使用临时文件避免自包含。
- 2026-01-30：Phase 3/4 增强——ida_analyze 支持复用现有 .i64/.idb 跳过分析。
- 2026-01-30：Phase 3/4 修复——reuseExisting 仅在匹配当前游戏数据库时生效。
- 2026-01-30：Phase 3/4 修复——默认 IDA 输出按游戏名分目录，避免库冲突。
- 2026-01-30：Phase 3/4 修复——复用校验加入数据库元信息（路径/大小/时间）。
- 2026-01-30：Phase 3/4 修复——复用校验加入 script.json 与 il2cpp.h 元信息。

- 2026-01-30：Phase 4/5 增强——导出调用关系/字符串，新增 analysis xrefs/strings 搜索 + 跨 job 索引缓存，并让 patch_codegen 生成目标清单 + IL2CPP hook 模板。
- 2026-01-30：Phase 3/4 增强——ida_register_db 支持导入外部 .i64/.idb 并写入 Kiln 元数据用于复用。
- 2026-01-30：发布结构——MCP 可从 publish/Plugins 目录加载插件 DLL，方便整理发布目录。
- 2026-01-30：Phase 5 修复——patch_codegen 生成 C# 字符串时转义控制字符，避免模板无法编译。
- 2026-01-30：仓库整理——.gitignore 忽略 publish/ 发布产物目录。
- 2026-01-30：文档——扩展 kiln.exampleFlow，加入每个工具的用途与注意事项。
- 2026-01-30：文档——补充最佳实践/常见错误/推荐顺序，并强制先读 exampleFlow。
- 2026-01-30：发布——新增 scripts/publish.ps1，一键构建并整理 publish/Kiln 目录结构。
- 2026-01-30：IDA 9.2 适配——支持 idat.exe/ida.exe 命名并更新配置示例。
- 2026-01-30：发布修复——导出脚本路径兼容 publish 根目录与 Plugins 目录。
- 2026-01-30：IDA 导出修复——打开现有 .i64/.idb 时跳过 -o，避免导出失败。
- 2026-01-30：IDA 命令修复——-S 参数改为单一引号串，确保脚本收到参数。
- 2026-01-30：IDA 命令修复——-S 后参数改为单独参数传入，确保脚本 ARGV 正确。
- 2026-01-30：IDA 命令修复——改为拼接 Arguments 字符串，-S 后传入带引号的脚本与参数。
- 2026-01-30：IDA 命令修复——-S 参数整体包一层引号，确保脚本参数不被拆分。
- 2026-01-30：IDA 命令修复——-S 在 Arguments 中直接使用带引号的脚本与参数（不额外转义）。
- 2026-01-30：IDA 命令修复——-S 脚本与参数始终加引号，避免 ARGV 丢失。
- 2026-01-31：IDA 命令修复 — 使用 Windows 命令行安全引用，确保 -S 脚本参数不被拆分。
- 2026-01-31：IDA 脚本改为环境变量兜底，避免 -S 参数解析丢失。
- 2026-01-31：IDA 导出兼容 — 在 get_inf_structure 不可用时回退 ida_ida.inf_get_*。
- 2026-01-31：IDA 导出修复 — 导出前清理残留的解包数据库文件，避免锁提示。
- 2026-01-31：伪代码按需导出 + 自动补齐搜索/获取 + 可选后台全量导出。
- 2026-01-31：patch_codegen 支持 jobId/gameDir/analysisDir 解析相对产物并自动回退分析目录。
- 2026-01-31：patch_codegen 过滤泛词、加入伪代码命中评分，并生成 HarmonyX 无敌 Hook。
- 2026-01-31：基于 Karate.Survivor 完成端到端闭环验证（复用 i64、导出符号、按需伪代码、生成 patch 模板）。
- 2026-01-31：新增 modsRoot 配置与 patch_codegen 自动生成按游戏划分的插件工程，并将 IDA 导出/伪代码自动导出改为后台任务避免超时。
- 2026-01-31：patch_codegen 输出改为 MOD 导向（BepInEx 插件），生成 mod_targets.json，移除默认 HarmonyX 补丁逻辑。
- 2026-01-31：新增 ida-pro-mcp stdio 代理，动态同步 ida.* 工具并进行实时转发。
- 2026-01-31：新增 patch_codegen 实时模式（基于 ida-pro-mcp，无需离线导出）并规范化 ida 工具 schema。
- 2026-01-31：新增 ida-pro-mcp 自动拉起能力，可基于数据库路径启动 IDA 供实时模式使用。
- 2026-01-31：新增 ida-pro-mcp 插件自动安装兜底，提升自动拉起成功率。
- 2026-01-31：自动拉起优先使用 ida.exe/ida64.exe（当配置为 idat.exe 时），并记录启动日志。
- 2026-01-31：自动拉起会清理未打包 DB 残留，并支持 headless 的 idat 启动。
- 2026-01-31：新增 ida-pro-mcp 自动拉起等待时长配置。

## 关键理念
- 关系数据以 symbols/strings 为主；伪代码按需导出并缓存，exportAll 可选且默认关闭。
- 分析产物优先通过 jobId/gameDir/analysisDir 解析相对路径，避免依赖绝对路径。
- HarmonyX 作为 IL2CPP 托管方法的默认补丁方案；原生地址 detour 为备选。
- 目标命中是启发式结果，发布前需要人工收敛（避免误补生命周期方法）。
- 使用任何工具前必须先读 kiln.exampleFlow（服务端强制）。

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

- 2026-01-31：ida-pro-mcp 自动启动强制使用 idat（headless），仅有 GUI IDA 时直接报错并拒绝启动。
- 2026-01-31：headless ida-pro-mcp 自动启动增加 -A，避免弹窗阻塞。
- 2026-01-31：live patch_codegen 在字符串检索/交叉引用超时后会回退到 ida.list_funcs。
- 2026-01-31：live patch_codegen 在调用 ida.* 之前会先自动拉起 IDA，避免连接竞态。
- 2026-01-31：新增 ida-pro-mcp 常驻保活循环并在启动时强制连通性检查。- 2026-02-01��ida-pro-mcp headless ʵʱͨ�ţ����� HTTP ������־������ headless �������̱߳ã��Զ������ű���Ϊ���б�+���·��ע�롣
- 2026-02-01������ ida-pro-mcp HTTP ��־·��͸�� + �����Լ죨tools/list + list_funcs + lookup_funcs��������¶�����
- 2026-02-01���޸� ida-pro-mcp HTTP ��־ f-string ת�����⣬ȷ�� stdio �������ڿ�����־ʱ������
