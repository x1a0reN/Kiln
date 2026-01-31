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

## Publish (recommended)
```
.\scripts\publish.ps1
```

This creates `publish\Kiln\` with:
- `Plugins\` (all Kiln.Plugins.* DLLs)
- `Tools\Il2CppDumper\`
- `ida\`, `workspace\`, `mods\`
- `kiln.config.template.json` + `kiln.config.json` (copied if missing)

## Run (stdio MCP)
```
dotnet run --project Kiln.Mcp -c Release
```

Optional logging:
- Set `KILN_MCP_LOG` to a file path to capture MCP logs.

## Config defaults
- `modsRoot` defaults to `mods\` under the Kiln root. `patch_codegen` will auto-generate per-game plugin projects here.

## MCP tools
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
- `ida_register_db`
- `ida_export_symbols`
- `ida_export_pseudocode`
- `analysis.index.build`
- `analysis.symbols.search`
- `analysis.symbols.get`
- `analysis.symbols.xrefs`
- `analysis.strings.search`
- `analysis.pseudocode.search`
- `analysis.pseudocode.get`
- `analysis.pseudocode.ensure`
- `patch_codegen`
- `package_mod`

## analysis.* usage (offline artifacts)
These tools operate on exported artifacts under `idaOutputDir` (default: `ida/`).

1) Export from IDA (Phase 4, async by default to avoid timeouts):
```json
{ "name": "ida_export_symbols", "arguments": { "jobId": "<jobId>", "async": true } }
{ "name": "ida_export_pseudocode", "arguments": { "jobId": "<jobId>", "async": true } }
```
Then poll `workflow.status` / `workflow.logs` for the export jobId.

2) Build indexes (optional but faster, cached across jobs):
```json
{ "name": "analysis.index.build", "arguments": { "jobId": "<jobId>" } }
```

3) Search symbols, strings, and pseudocode:
```json
{ "name": "analysis.symbols.search", "arguments": { "jobId": "<jobId>", "query": "Player", "field": "name", "match": "contains", "limit": 20 } }
{ "name": "analysis.symbols.search", "arguments": { "jobId": "<jobId>", "query": "0x1801234", "field": "ea", "match": "exact", "limit": 5 } }
{ "name": "analysis.symbols.search", "arguments": { "jobId": "<jobId>", "query": "void Player", "field": "signature", "match": "contains", "limit": 10 } }
{ "name": "analysis.strings.search", "arguments": { "jobId": "<jobId>", "query": "weapon", "match": "contains", "includeRefs": true, "maxRefs": 20 } }
{ "name": "analysis.pseudocode.search", "arguments": { "jobId": "<jobId>", "query": "weaponId", "limit": 10, "snippetChars": 300 } }
```

4) Fetch details:
```json
{ "name": "analysis.symbols.get", "arguments": { "jobId": "<jobId>", "name": "Player_Update" } }
{ "name": "analysis.symbols.xrefs", "arguments": { "jobId": "<jobId>", "name": "Player_Update", "direction": "both", "limit": 50 } }
{ "name": "analysis.pseudocode.get", "arguments": { "jobId": "<jobId>", "name": "Player_Update", "maxChars": 4000 } }
```
If pseudocode is missing, `analysis.pseudocode.get` will start a background export and return `pending` + `exportJobId`.

Tip: if `idaOutputDir` already contains a matching `.i64/.idb`, `ida_analyze` can skip analysis by passing `reuseExisting: true`.

If you have a pre-existing `.i64/.idb` from manual IDA work, register it first:
```json
{ "name": "ida_register_db", "arguments": { "gameDir": "<gameDir>", "databasePath": "D:\\Path\\GameAssembly.i64", "copyToIdbDir": true, "overwrite": false } }
```
Note: this validates `script.json` + `il2cpp.h` from the configured `il2cppRootDir` dump folder and writes a `.kiln.json` meta file next to the DB.

`patch_codegen` will also emit a per-game plugin project under `modsRoot` when `gameDir` or `jobId` is provided (disable with `emitPluginProject: false`).

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
