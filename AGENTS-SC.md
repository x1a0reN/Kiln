# AGENTS（简体中文）

## 背景
- 目标：构建 dnSpyEx 的 MCP 插件，提供本地 IPC 服务器与 stdio bridge，让 MCP 客户端可与 dnSpyEx UI 通信。
- 仓库：<repo-root>

## 目标架构
- dnSpyEx 插件内置本地 IPC（优先 NamedPipe，可选 HTTP）。
- 独立 MCP stdio bridge（控制台）负责 stdio JSON-RPC，并转发到 IPC。
- 暴露 MVP 工具：程序集 / 命名空间 / 类型 / 成员 / 反编译 / 选中文本。

## 项目结构（MCP 相关）
- Extensions\dnSpyEx.MCP\dnSpyEx.MCP.csproj：扩展项目；引用 dnSpy 合约与 Newtonsoft.Json。
- Extensions\dnSpyEx.MCP\TheExtension.cs：扩展入口；AppLoaded 启动服务，AppExit 停止服务。
- Extensions\dnSpyEx.MCP\McpHost.cs：MEF 导出宿主；将 dnSpy 服务注入 IPC 服务端。
- Extensions\dnSpyEx.MCP\Ipc\McpIpcServer.cs：NamedPipe JSON-RPC 服务端（按行分隔）；支持 DNSPYEX_MCP_PIPE 覆盖。
- Extensions\dnSpyEx.MCP\Ipc\McpRequestHandler.cs：RPC 分发 + MVP 工具；在 UI 线程执行。
- Tools\dnSpyEx.MCP.Bridge\dnSpyEx.MCP.Bridge.csproj：MCP stdio bridge 控制台项目。
- Tools\dnSpyEx.MCP.Bridge\Program.cs：bridge 入口；运行 MCP 循环（按需连接管道）。
- Tools\dnSpyEx.MCP.Bridge\McpServer.cs：MCP JSON-RPC（initialize/tools/*）；转发工具调用到管道。
- Tools\dnSpyEx.MCP.Bridge\ToolCatalog.cs：工具定义与输入 schema，映射到 RPC 方法。
- Tools\dnSpyEx.MCP.Bridge\ResourceCatalog.cs：内置 MCP 资源（BepInEx 文档），并支持 resources/list 与 resources/read。
- Tools\dnSpyEx.MCP.Bridge\PipeClient.cs：NamedPipe 客户端（按行 JSON），延迟连接带超时。
- Tools\dnSpyEx.MCP.Bridge\McpPipeDefaults.cs：管道名常量与环境变量名。
- dnSpyEx.MCP.slnx：只包含 dnSpyEx.MCP 与 dnSpyEx.MCP.Bridge 的解决方案。

## 决策
- 采用混合模型：插件端暴露 NamedPipe（或 HTTP），bridge 负责 stdio MCP。
- 先实现 MVP 工具集，再逐步扩展。

## 当前进度
- 2026-01-29：创建 AGENTS.md。
- 2026-01-29：新增 dnSpyEx.MCP 扩展项目，内置 NamedPipe JSON-RPC 服务与 MVP 处理器。
- 2026-01-29：新增 dnSpyEx.MCP.Bridge 控制台项目（stdio MCP -> NamedPipe）。
- 2026-01-29：本机构建失败，因 .NET SDK 9 不支持 net10.0-windows（NETSDK1045）；需安装 .NET 10 SDK。
- 2026-01-29：将 AGENT-sc.md 改名为 AGENTS-SC.md 统一命名。
- 2026-01-29：修复 McpRequestHandler 的 UTF8String 序列化与可空 MVID 处理；bridge 目标设为 net10.0-windows。
- 2026-01-29：build.ps1 -NoMsbuild 在本机超时；已单独构建 dnSpyEx.MCP（net10.0-windows）与 dnSpyEx.MCP.Bridge（net10.0-windows），0 错误。
- 2026-01-29：扩展程序集名改为 dnSpyEx.MCP.x；构建 dnSpyEx.MCP（net10.0-windows）0 警告，无错误。
- 2026-01-29：新增 Output 窗口日志（MCP 服务/请求）；构建 dnSpyEx.MCP（net10.0-windows）0 警告，无错误。
- 2026-01-29：新增基于 DnSpyExBin 的外部引用；构建 net10.0-windows 成功。
- 2026-01-29：新增 Output 日志与对 BamlTabSaver NullReferenceException 的定向抑制；在 BamlTabSaver 加入空引用保护。
- 2026-01-29：bridge 改为首次工具调用时才连接管道（懒连接），失败时重置管道，避免启动即报 “Pipe hasn't been connected yet”。
- 2026-01-29：插件端新增管道读写错误日志；bridge 侧对“断开的管道”做一次重连重试以缓解偶发错误。
- 2026-01-29：插件构建默认自动复制 dnSpyEx.MCP.x.dll 到 C:\Path\dnSpyEx\bin\Extensions（如需可通过 DnSpyExInstallDir 覆盖）。
- 2026-01-29：新增 NamedPipe 安全设置（仅当前用户）与服务端创建错误处理；移除强制完整性标签以避免权限错误，并修复退出时由 TimeSpan.FromSeconds(long) 触发的崩溃。
- 2026-01-29：服务端允许多个 NamedPipe 客户端并行连接（最大实例数），避免旧连接占用导致新连接超时。
- 2026-01-29：新增更详细的管道 I/O 日志（按客户端记录请求/EOF/错误），用于定位 “Pipe closed” 早退问题。
- 2026-01-29：新增 bridge 端可选文件日志（DNSPYEX_MCP_BRIDGE_LOG），用于跟踪 stdio 与 pipe 流程且不污染 MCP stdout。
- 2026-01-29：新增每个客户端处理器生命周期日志与异常捕获，便于定位连接后立刻断开的原因。
- 2026-01-29：将 JToken.ToString(Formatting) 替换为 JsonConvert.SerializeObject，避免 dnSpyEx 运行时 Newtonsoft.Json 版本不匹配崩溃。
- 2026-01-29：管道安全权限增加 CreateNewInstance，避免创建额外服务端实例时报 “Access denied”。
- 2026-01-29：允许 listTypes/decompile 的 namespace 为空字符串；新增 dnspy.help 工具并在 tools/list 中提供说明。
- 2026-01-29：新增 dnspy.exampleFlow 工具，提供各工具完整用法示例，并在描述中提示优先阅读。
- 2026-01-29：补全 dnspy.exampleFlow，明确包含 dnspy.help 等文档工具的用法说明。
- 2026-01-29：dnspy.exampleFlow 覆盖全部工具用法，新增方法/字段/类型信息工具，并加入 dnspy.search（完整参数）。
- 2026-01-29：dnspy.search 改为基于 dnlib 的自定义搜索（元数据 + IL/正文文本），避免内部搜索 API；更新模块键与 UTF8String 处理。
- 2026-01-30：迁移 MCP 插件与 bridge 到独立仓库，并将插件固定为 net10.0-windows + dnSpyEx 二进制引用（DnSpyExBin）。
- 2026-01-30：新增 dnSpyEx.MCP.slnx，简化 DnSpyCommon.props（移除构建任务导入），固定独立构建走 DnSpyExBin；补充 .gitignore。
- 2026-01-30：清理独立仓库结构（保留 Extensions\dnSpyEx.MCP）并移除已跟踪构建产物；扩展 .gitignore 覆盖 bin/obj。
- 2026-01-30：新增独立仓库 README（构建/运行与二进制依赖说明），并移除旧 dnSpyEx.MCP fork 的远端以避免混淆。
- 2026-01-30：bridge 新增 MCP 资源支持（resources/list、resources/read），内置 BepInEx 文档资源库。
- 2026-01-30：新增 dnSpyEx MCP 资源索引文档（dnspyex://docs/resource-index），用于引导 AI 客户端读取资源。
- 2026-01-30：移除 Tools 根目录中的旧 bridge 文件，bridge 仅保留在 Tools\dnSpyEx.MCP.Bridge。
- 2026-01-30：面向发布重写 README，加入英文描述与多客户端 MCP 配置示例。
- 2026-01-30：对 README 与 AGENTS 路径脱敏，移除个人目录名。

## 下一步
- 构建并确认两个项目可正常编译。
- 启动 dnSpyEx 并验证 AppLoaded 时 NamedPipe 服务正常启动。
- 运行 bridge 并测试 MCP 调用：listAssemblies / listNamespaces / listTypes / listMembers / decompile / getSelectedText。

## 构建与使用指南

### 前置条件
- .NET SDK 10.x（仓库目标为 net10.0-windows）。
- 需要本机 dnSpyEx 二进制；如路径不同请设置 DnSpyExBin。

### 构建
```
dotnet build Extensions\dnSpyEx.MCP\dnSpyEx.MCP.csproj -c Release -f net10.0-windows
```

```
dotnet build Tools\dnSpyEx.MCP.Bridge\dnSpyEx.MCP.Bridge.csproj -c Release -f net10.0-windows
```

说明：
- 需要 dnSpyEx 二进制；如安装路径不同请设置 DnSpyExBin。

### 运行 dnSpyEx + MCP bridge
1) 启动 dnSpyEx（已安装 net10 构建）：
```
C:\Path\dnSpyEx\bin\dnSpy.exe
```

2) 启动 MCP bridge：
```
dotnet run --project Tools/dnSpyEx.MCP.Bridge -c Release
```

### 管道配置
- 默认管道名：`dnSpyEx.MCP`
- 环境变量覆盖：`DNSPYEX_MCP_PIPE`
- bridge 参数：`--pipe <name>`

### 可用 MCP 工具（MVP）
- dnspy.help
- dnspy.exampleFlow
- dnspy.listAssemblies
- dnspy.listNamespaces
- dnspy.listTypes
- dnspy.listMembers
- dnspy.decompile
- dnspy.decompileMethod
- dnspy.decompileField
- dnspy.decompileProperty
- dnspy.decompileEvent
- dnspy.getFieldInfo
- dnspy.getEnumInfo
- dnspy.getStructInfo
- dnspy.getInterfaceInfo
- dnspy.search
- dnspy.getSelectedText

### 接入 AI IDE（支持 MCP）
通用思路：在 IDE 中把 bridge 配置为 stdio MCP server。示例配置：

```json
{
  "mcpServers": {
    "dnspyex": {
      "command": "dotnet",
      "args": [
        "run",
        "--project",
        "Tools/dnSpyEx.MCP.Bridge",
        "-c",
        "Release"
      ],
      "env": {
        "DNSPYEX_MCP_PIPE": "dnSpyEx.MCP"
      }
    }
  }
}
```

流程：
1) 先启动 dnSpyEx（插件在 AppLoaded 启动管道）。
2) 启动 IDE MCP 服务（bridge 连接管道）。
3) 使用 IDE 工具列表里的 MCP 工具。

## 备注
- 用户要求每次更新都记录进度到 AGENTS.md。
- 用户确认仅使用 .NET 10；构建命令保持自动复制开启（不要设置 DisableDnSpyExInstallCopy）。
- 工作目录：<repo-root>
- 参考源码目录（只读）：<dnSpyEx-source-path>

## 规则
- 每次改动后确认构建无错误，然后提交并推送。
- 每次代码改动后更新 AGENTS.md 的进度。
- AGENTS.md 变更后同步更新 AGENTS-SC.md（规则块本身除外）。
- 每新增一个 MCP 工具，都要在 dnspy.exampleFlow 中补充该工具的用法与示例。
