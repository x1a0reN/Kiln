# dnSpyEx.MCP (Standalone)

English description:
dnSpyEx MCP extension and stdio bridge that expose local decompilation tools to AI clients via a NamedPipe IPC.

这是一个独立仓库，仅包含 dnSpyEx 的 MCP 插件与 stdio bridge，不包含 dnSpyEx 源码。

## 功能特性
- 插件端在 dnSpyEx 内启动本地 NamedPipe IPC（JSON-RPC，按行分隔）。
- bridge 端通过 stdio 提供 MCP 服务，转发到本地 NamedPipe。
- 内置 MCP Resources：BepInEx v6 文档与资源索引。
- 工具覆盖：程序集/命名空间/类型/成员枚举、反编译、搜索、选中文本等。

## 项目结构
- `Extensions/dnSpyEx.MCP`: dnSpyEx 扩展（插件）。
- `Tools/dnSpyEx.MCP.Bridge`: MCP stdio bridge 控制台程序。
- `dnSpyEx.MCP.slnx`: 只包含插件与 bridge 的解决方案。

## 前置条件
- Windows
- .NET SDK 10.x
- 本机已安装 dnSpyEx，可访问其二进制目录（默认路径可覆盖）

默认二进制目录（可覆盖）：
```
C:\Path\dnSpyEx\bin
```

## 构建
插件：
```
dotnet build Extensions\dnSpyEx.MCP\dnSpyEx.MCP.csproj -c Release -f net10.0-windows
```

bridge：
```
dotnet build Tools\dnSpyEx.MCP.Bridge\dnSpyEx.MCP.Bridge.csproj -c Release -f net10.0-windows
```

指定 dnSpyEx 二进制路径（若安装路径不同）：
```
dotnet build Extensions\dnSpyEx.MCP\dnSpyEx.MCP.csproj -c Release -f net10.0-windows -p:DnSpyExBin="C:\Path\dnSpyEx\bin"
```

插件默认会自动复制到 dnSpyEx 扩展目录；如需自定义扩展目录：
```
-p:DnSpyExInstallDir="C:\Path\dnSpyEx\bin\Extensions"
```

## 运行
1) 启动 dnSpyEx：
```
C:\Path\dnSpyEx\bin\dnSpy.exe
```

2) 启动 MCP bridge：
```
dotnet run --project Tools/dnSpyEx.MCP.Bridge -c Release
```

## 管道配置
- 默认管道名：`dnSpyEx.MCP`
- 环境变量覆盖：`DNSPYEX_MCP_PIPE`
- bridge 参数：`--pipe <name>`

## MCP 工具（MVP）
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

## MCP Resources
资源列表与读取：
- `resources/list`
- `resources/read`（参数：`{ "uri": "<resource-uri>" }`）

资源索引（建议先读）：
- `dnspyex://docs/resource-index`

BepInEx 文档资源：
- `bepinex://docs/plugin-structure`
- `bepinex://docs/harmony-patching`
- `bepinex://docs/configuration`
- `bepinex://docs/common-scenarios`
- `bepinex://docs/il2cpp-guide`
- `bepinex://docs/mono-vs-il2cpp`

## MCP 配置（主流 AI 客户端）
说明：以下为通用 MCP Server 配置片段。不同客户端的配置入口/文件路径可能不同，请按客户端官方文档放置配置。

通用配置片段（请按需修改）：
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

### Claude Desktop
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

### Cursor
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

### Cline (VS Code)
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

### Continue (VS Code / JetBrains)
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

### Windsurf
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

## 使用建议
1) 先启动 dnSpyEx（插件会在 AppLoaded 启动管道）。
2) 再启动 MCP bridge。
3) 在 AI 客户端中调用 `resources/list`，读取资源索引与 BepInEx 文档。
4) 通过 `dnspy.list*` / `dnspy.decompile*` / `dnspy.search` 完成分析流程。
