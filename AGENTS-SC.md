# AGENTS（简体中文）

## 背景
- 目标：为 dnSpyEx 构建 MCP 插件，通过本地 IPC + stdio bridge 让 MCP 客户端与 dnSpyEx UI 交互。
- 仓库：D:\Projects\dnSpyEx.MCP.Standalone

## 目标架构
- dnSpyEx 插件内置本地 IPC（优先 NamedPipe，可选 HTTP）。
- 独立的 MCP stdio bridge（控制台）负责 stdio JSON-RPC，并转发到 IPC。
- 暴露 MVP 工具：程序集 / 命名空间 / 类型 / 成员 / 反编译 / 选中代码。

## 项目结构（MCP 相关）
- Extensions\dnSpyEx.MCP\dnSpyEx.MCP.csproj：扩展项目，引用 dnSpy 合约与 Newtonsoft.Json。
- Extensions\dnSpyEx.MCP\TheExtension.cs：扩展入口，在 AppLoaded 启动服务、AppExit 停止服务。
- Extensions\dnSpyEx.MCP\McpHost.cs：MEF 导出宿主，将 dnSpy 服务注入 IPC 服务器。
- Extensions\dnSpyEx.MCP\Ipc\McpIpcServer.cs：NamedPipe JSON-RPC 服务器（按行读取）；支持 DNSPYEX_MCP_PIPE 覆盖管道名。
- Extensions\dnSpyEx.MCP\Ipc\McpRequestHandler.cs：RPC 分发与 MVP 工具实现；在 UI 线程执行。
- Tools\dnSpyEx.MCP.Bridge\dnSpyEx.MCP.Bridge.csproj：MCP stdio bridge 控制台项目。
- Tools\dnSpyEx.MCP.Bridge\Program.cs：bridge 入口，运行 MCP 循环（按需连接管道）。
- Tools\dnSpyEx.MCP.Bridge\McpServer.cs：MCP JSON-RPC（initialize/tools/*）；将工具调用转发到管道。
- Tools\dnSpyEx.MCP.Bridge\ToolCatalog.cs：工具定义与输入 schema，映射到 RPC 方法。
- Tools\dnSpyEx.MCP.Bridge\PipeClient.cs：NamedPipe 客户端（按行传 JSON），按需连接并带超时。
- Tools\dnSpyEx.MCP.Bridge\McpPipeDefaults.cs：管道名常量与环境变量名。
- dnSpyEx.MCP.slnï¼ä»
å
å« dnSpyEx.MCP ä¸ dnSpyEx.MCP.Bridge çè§£å³æ¹æ¡ã

## 决策
- 采用混合式：插件侧暴露 NamedPipe（或 HTTP），bridge 负责 stdio MCP。
- 先实现 MVP 工具集，再逐步扩展。

## 当前进度
- 2026-01-29：创建 AGENTS.md。
- 2026-01-29：新增 dnSpyEx.MCP 扩展项目，内置 NamedPipe JSON-RPC 服务与 MVP 处理器。
- 2026-01-29：新增 dnSpyEx.MCP.Bridge 控制台项目（stdio MCP -> NamedPipe）。
- 2026-01-29：在本机尝试构建失败，原因是 .NET SDK 9 不支持 net10.0-windows（NETSDK1045）；需安装 .NET 10 SDK。
- 2026-01-29：将 AGENT-sc.md 重命名为 AGENTS-SC.md，以统一命名。
- 2026-01-29：修复 McpRequestHandler 中 UTF8String 序列化与可空 MVID 处理；将 bridge 目标框架改为 net10.0-windows。
- 2026-01-29：build.ps1 -NoMsbuild 在本机超时；已单独构建 dnSpyEx.MCP（net10.0-windows）与 dnSpyEx.MCP.Bridge（net10.0-windows），均 0 错误。
- 2026-01-29：扩展程序集名改为 dnSpyEx.MCP.x；构建 dnSpyEx.MCP：net10.0-windows（0 警告），均无错误。
- 2026-01-29：新增 Output 窗口日志输出（MCP 服务/请求）；构建 dnSpyEx.MCP：net10.0-windows（0 警告），均无错误。
- 2026-01-29：为插件新增 目标并通过 DnSpyExBin 引用外部依赖；bridge 目标为 net10.0-windows；net10 构建均成功。
- 2026-01-29：新增 Output 日志输出及对 BamlTabSaver NullReferenceException 的定向抑制；并在 BamlTabSaver 中加入空引用保护。
- 2026-01-29：由于本仓库源码与已安装的 二进制存在 API 不匹配，无法直接编译 版 dnSpy.BamlDecompiler；已通过插件抑制崩溃作为替代方案。
- 2026-01-29：bridge 改为首次工具调用时再连接管道（懒连接），并在失败时重置管道，避免启动即报 “Pipe hasn't been connected yet”。
- 2026-01-29：插件端新增管道读写错误日志，bridge 侧对“断开的管道”做一次重连重试以缓解偶发错误。
- 2026-01-29ï¼æä»¶æå»ºåé»è®¤èªå¨å¤å¶ dnSpyEx.MCP.x.dll å° D:\u9006å\u5de5å
·-éå\dnspyEx\bin\Extensionsï¼å¯ç¨ DisableDnSpyExInstallCopy=true å
³é­ï¼æéè¿ DnSpyExInstallDir è¦çè·¯å¾ï¼ã
- 2026-01-29：新增 NamedPipe 安全设置（仅当前用户）并补充服务器创建错误处理；移除强制完整性标签以避免权限错误，并修复 退出时因 TimeSpan.FromSeconds(long) 触发的崩溃。
- 2026-01-29：服务器现在允许多个 NamedPipe 客户端并行连接（最大实例数），避免旧连接占用导致新连接超时。
- 2026-01-29：新增更详细的管道 I/O 日志（按客户端记录请求/EOF/错误），用于定位 “Pipe closed” 早退问题。
- 2026-01-29：新增 bridge 端可选文件日志（DNSPYEX_MCP_BRIDGE_LOG），用于追踪 stdio 与 pipe 流程且不污染 MCP stdout。
- 2026-01-29：新增每个客户端处理器的生命周期日志与异常捕获，便于定位连接后立即断开的原因。
- 2026-01-29：将 JToken.ToString(Formatting) 替换为 JsonConvert.SerializeObject，避免 dnSpyEx 运行时 Newtonsoft.Json 版本不匹配导致的崩溃。
- 2026-01-29：管道安全权限增加 CreateNewInstance，避免创建额外服务器实例时报 “Access denied” 日志刷屏。
- 2026-01-29：允许 listTypes/namespace decompile 的 namespace 为空字符串，并新增 dnspy.help 工具在 tools/list 中提供使用说明。
- 2026-01-29：新增 dnspy.exampleFlow 工具，提供各工具的完整用法示例，并在工具描述中提示优先阅读。
- 2026-01-29：补充 dnspy.exampleFlow，明确包含 dnspy.help 等文档工具的用法说明。
- 2026-01-29：dnspy.exampleFlow 现覆盖全部工具用法，新增方法/字段/类型信息工具，并加入 dnspy.search（完整搜索参数）。
- 2026-01-30ï¼å·²è¿ç§» MCP æä»¶ä¸ bridge å°ç¬ç«ä»åºï¼å¹¶å°æä»¶åæ¢ä¸º net10.0-windows ä¸ä½¿ç¨ DnSpyExBin äºè¿å¶å¼ç¨ã
- 2026-01-30ï¼æ°å¢ dnSpyEx.MCP.slnxï¼ç®å DnSpyCommon.propsï¼ç§»é¤æå»ºä»»å¡å¯¼å¥ï¼ï¼å¹¶å°ç¬ç«æå»ºåºå®ä¸º DnSpyExBin å¼ç¨ï¼æ·»å  bridge æ¥å¿ .gitignoreã
- 2026-01-29: dnspy.search switched to a dnlib-based custom search (metadata + IL/body text), avoiding internal search APIs; updated module keys and UTF8String handling.

## 下一步
- 编译解决方案，确认两个新项目可正常构建。
- 启动 dnSpyEx 并验证 AppLoaded 后 NamedPipe 服务器正常启动。
- 运行 bridge 并测试 MCP 调用：listAssemblies / listNamespaces / listTypes / listMembers / decompile / getSelectedText。

## 构建与使用指南

### 前置条件
- .NET SDK 10.x（仓库目标为 net10.0-windows）。
- éè¦æ¬å° dnSpyEx äºè¿å¶ï¼è·¯å¾ä¸åè¯·è®¾ç½® DnSpyExBinï¼ã

### 构建
```
dotnet build Extensions\dnSpyEx.MCP\dnSpyEx.MCP.csproj -c Release -f net10.0-windows
```

```
dotnet build Tools\dnSpyEx.MCP.Bridge\dnSpyEx.MCP.Bridge.csproj -c Release -f net10.0-windows
```

è¯´æï¼
- éè¦ dnSpyEx äºè¿å¶ï¼è·¯å¾ä¸åè¯·è®¾ç½® DnSpyExBinã

### 运行 dnSpyEx + MCP bridge
1) 启动 dnSpyEx（net10.0-windows 输出）：
```
D:\??\??-??\dnspyEx\bin\dnSpy.exe
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
思路：在 IDE 中把 bridge 配置为 stdio MCP server。通用配置示例：

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
1) 先启动 dnSpyEx（插件在 AppLoaded 时启动管道）。
2) 启动 IDE 的 MCP server（bridge 连接管道）。
3) 在 IDE 的 MCP 工具列表中调用工具。

## 备注
- 用户要求每次进度更新都同步记录到 AGENTS.md。
- 用户确认只使用 .NET 10 构建（不再使用 net48），并要求构建时不要使用 DisableDnSpyExInstallCopy=true 以便自动复制插件。
