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
- Set `idaMcpHttpLogPath` in config to capture ida-pro-mcp HTTP proxy logs.

## Config defaults
- `modsRoot` defaults to `mods\` under the Kiln root. `patch_codegen` will auto-generate per-game plugin projects here.
- `idaMcpEnabled` in the template defaults to true to favor live ida-pro-mcp analysis.

## ida-pro-mcp proxy (live IDA tools)
Kiln can spawn `ida-pro-mcp` as a stdio child process and expose its tool list as `ida.*` tools.

Requirements:
- Install ida-pro-mcp and the IDA plugin (RPC server).
- Ensure the IDA plugin RPC is reachable (default: `http://127.0.0.1:13337`).
- Fork pin: `_external/ida-pro-mcp` uses `https://github.com/x1a0reN/ida-pro-mcp` at commit `94edf24afa6faa6696471ce9f61dd2385d376593` for headless realtime support.

Example config (kiln.config.json):
```json
{
  "idaMcpEnabled": true,
  "idaMcpAutoStart": true,
  "idaMcpHeadless": true,
  "idaMcpAutoStartWaitSeconds": 180,
  "idaMcpResident": true,
  "idaMcpResidentPingSeconds": 10,
  "idaMcpHttpLogPath": "workspace\\ida_mcp_http.log",
  "idaMcpHealthCheckEnabled": true,
  "idaMcpHealthCheckTimeoutSeconds": 30,
  "idaMcpDatabasePath": "D:\\Game\\Example\\Reverse\\GameAssembly.dll.i64",
  "idaMcpCommand": "ida-pro-mcp",
  "idaMcpArgs": [
    "--transport",
    "stdio",
    "--ida-rpc",
    "http://127.0.0.1:13337"
  ]
}
```
When enabled, `tools/list` will include `ida.*` entries and `tools/call` will forward to ida-pro-mcp in real time.
When `idaMcpAutoStart` is true, Kiln can spawn IDA with the configured database path to start the MCP server automatically.
When `idaMcpHealthCheckEnabled` is true, Kiln runs a lightweight ida-pro-mcp self-test on startup (tools/list + list_funcs + lookup_funcs).

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
- `ida.*` (proxied from ida-pro-mcp when configured)

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

`patch_codegen` will also emit a per-game plugin project under `modsRoot` when `gameDir` or `jobId` is provided (disable with `emitPluginProject: false`). It now outputs `mod_targets.json` and a mod-oriented plugin template (no default Harmony patching).
`patch_codegen` supports a live mode via ida-pro-mcp. Use `analysisMode: "live"` (or leave `auto` to prefer ida-pro-mcp when enabled) to generate targets from real-time IDA queries without exporting artifacts.

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
