# dnSpyEx.MCP（独立仓库）

本仓库仅包含 dnSpyEx 的 MCP 插件与 stdio bridge，不包含 dnSpyEx 源码。

## 架构概览
- 插件端：dnSpyEx 内部启动 NamedPipe IPC 服务（JSON-RPC，按行分隔）。
- bridge 端：stdio MCP 服务器，转发工具调用到 NamedPipe。

## 前置条件
- .NET SDK 10.x
- 本机已安装 dnSpyEx，并可访问其二进制目录

默认二进制目录（可覆盖）：
```
D:\逆向\工具-逆向\dnspyEx\bin
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

### 指定 dnSpyEx 二进制路径
如安装路径不同，使用 `DnSpyExBin` 覆盖：
```
dotnet build Extensions\dnSpyEx.MCP\dnSpyEx.MCP.csproj -c Release -f net10.0-windows -p:DnSpyExBin="D:\你的路径\dnSpyEx\bin"
```

插件默认会自动复制到 dnSpyEx 扩展目录；如需自定义扩展目录，设置：
```
-p:DnSpyExInstallDir="D:\你的路径\dnSpyEx\bin\Extensions"
```

## 运行
1) 启动 dnSpyEx：
```
D:\逆向\工具-逆向\dnspyEx\bin\dnSpy.exe
```

2) 启动 MCP bridge：
```
dotnet run --project Tools/dnSpyEx.MCP.Bridge -c Release
```

## 管道配置
- 默认管道名：`dnSpyEx.MCP`
- 环境变量：`DNSPYEX_MCP_PIPE`
- bridge 参数：`--pipe <name>`

## 如何“引用”dnSpyEx 源码
本仓库**不**直接引用 dnSpyEx 源码，只依赖 dnSpyEx 的二进制（通过 `DnSpyExBin` 指定）。

为了后续功能开发需要查看 API 或实现细节，你可以在本机**单独保留** dnSpyEx 源码仓库作为“参考仓库”，例如：
```
D:\Projects\dnSpyEx.Source
```

之后我会在需要时读取该路径下的源码进行对照，但**构建仍只依赖二进制**。如果你希望改成子模块或固定到某个提交，也可以告诉我你的偏好。

