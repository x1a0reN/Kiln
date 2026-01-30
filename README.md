# Kiln

English description:
Kiln is a Windows-only MCP server focused on game reverse engineering workflows, starting with a Unity IL2CPP end-to-end pipeline.

## Scope (v0.1)
- Windows only
- stdio MCP server (streamable HTTP later)
- Unity IL2CPP vertical workflow (Il2CppDumper + IDA Pro)
- Embedded MCP resources (BepInEx docs)

## Repository layout
- `Kiln.Mcp`: stdio MCP server (single external entrypoint)
- `Kiln.Core`: workflow + job + artifact core (planned)
- `Kiln.Plugins/Unity.Il2Cpp`: Unity IL2CPP pipeline (planned)
- `Kiln.Plugins/Ida.Pro`: IDA headless automation (planned)
- `Kiln.Plugins/DotNetAnalysis`: .NET analysis helpers (planned)
- `Kiln.Plugins/Packaging`: packaging + manifests (planned)
- `Kiln.slnx`: solution for the Kiln projects

## Prerequisites
- Windows
- .NET SDK 10.x

## Build
```
dotnet build Kiln.slnx -c Release
```

## Run (stdio MCP)
```
dotnet run --project Kiln.Mcp -c Release
```

Optional logging:
- Set `KILN_MCP_LOG` to a file path to capture MCP logs.

## MCP tools (Phase 0 stubs)
- `kiln.help`
- `kiln.exampleFlow`
- `workflow.run`
- `workflow.status`
- `workflow.logs`
- `workflow.cancel`
- `detect_engine`
- `unity_locate`
- `il2cpp_dump`
- `ida_analyze`
- `ida_export_symbols`
- `ida_export_pseudocode`
- `patch_codegen`
- `package_mod`

## MCP resources
- List: `resources/list`
- Read: `resources/read` with `{ "uri": "<resource-uri>" }`
- Resource index: `kiln://docs/resource-index`

### BepInEx docs
- `bepinex://docs/plugin-structure`
- `bepinex://docs/harmony-patching`
- `bepinex://docs/configuration`
- `bepinex://docs/common-scenarios`
- `bepinex://docs/il2cpp-guide`
- `bepinex://docs/mono-vs-il2cpp`

## MCP configs (popular AI clients)

Generic MCP config snippet:
```json
{
  "mcpServers": {
    "kiln": {
      "command": "dotnet",
      "args": [
        "run",
        "--project",
        "Kiln.Mcp",
        "-c",
        "Release"
      ]
    }
  }
}
```

### Claude Desktop
```json
{
  "mcpServers": {
    "kiln": {
      "command": "dotnet",
      "args": [
        "run",
        "--project",
        "Kiln.Mcp",
        "-c",
        "Release"
      ]
    }
  }
}
```

### Cursor
```json
{
  "mcpServers": {
    "kiln": {
      "command": "dotnet",
      "args": [
        "run",
        "--project",
        "Kiln.Mcp",
        "-c",
        "Release"
      ]
    }
  }
}
```

### Cline (VS Code)
```json
{
  "mcpServers": {
    "kiln": {
      "command": "dotnet",
      "args": [
        "run",
        "--project",
        "Kiln.Mcp",
        "-c",
        "Release"
      ]
    }
  }
}
```

### Continue (VS Code / JetBrains)
```json
{
  "mcpServers": {
    "kiln": {
      "command": "dotnet",
      "args": [
        "run",
        "--project",
        "Kiln.Mcp",
        "-c",
        "Release"
      ]
    }
  }
}
```

### Windsurf
```json
{
  "mcpServers": {
    "kiln": {
      "command": "dotnet",
      "args": [
        "run",
        "--project",
        "Kiln.Mcp",
        "-c",
        "Release"
      ]
    }
  }
}
```
