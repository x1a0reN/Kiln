# AGENTS

## Background
- Goal: build a dnSpyEx MCP plugin with a local IPC server and a stdio bridge so MCP clients can talk to dnSpyEx UI.
- Repo: D:\Projects\dnSpyEx.MCP.Standalone

## Target Architecture
- dnSpyEx plugin hosts a local IPC server (NamedPipe preferred; HTTP optional).
- Separate MCP stdio bridge (console app) speaks MCP JSON-RPC over stdio and forwards to the IPC server.
- Expose MVP tools: assembly / namespace / type / member / decompile / selected code.

## Project Structure (MCP-related)
- Extensions\dnSpyEx.MCP\dnSpyEx.MCP.csproj: Extension project; references dnSpy contracts and Newtonsoft.Json.
- Extensions\dnSpyEx.MCP\TheExtension.cs: Extension entrypoint; starts server on AppLoaded and stops on AppExit.
- Extensions\dnSpyEx.MCP\McpHost.cs: MEF-exported host; wires dnSpy services into the IPC server.
- Extensions\dnSpyEx.MCP\Ipc\McpIpcServer.cs: NamedPipe JSON-RPC server (line-delimited); supports DNSPYEX_MCP_PIPE override.
- Extensions\dnSpyEx.MCP\Ipc\McpRequestHandler.cs: RPC dispatch + MVP tools; runs on UI dispatcher.
- Tools\dnSpyEx.MCP.Bridge\dnSpyEx.MCP.Bridge.csproj: MCP stdio bridge console app.
- Tools\dnSpyEx.MCP.Bridge\Program.cs: Bridge entrypoint; runs MCP loop (pipe connects on demand).
- Tools\dnSpyEx.MCP.Bridge\McpServer.cs: MCP JSON-RPC (initialize/tools/*); forwards tool calls to pipe.
- Tools\dnSpyEx.MCP.Bridge\ToolCatalog.cs: Tool definitions and input schemas mapped to RPC methods.
- Tools\dnSpyEx.MCP.Bridge\ResourceCatalog.cs: Embedded MCP resources (BepInEx docs) and resource list/read support.
- Tools\dnSpyEx.MCP.Bridge\PipeClient.cs: NamedPipe client (line-delimited JSON), lazy connect with timeout.
- Tools\dnSpyEx.MCP.Bridge\McpPipeDefaults.cs: Pipe name constants and env var name.
- dnSpyEx.MCP.slnx: Solution containing dnSpyEx.MCP and dnSpyEx.MCP.Bridge only.

## Decisions
- Use hybrid model: plugin exposes NamedPipe (or HTTP) and bridge handles stdio MCP.
- Focus on MVP toolset first, then expand.

## Current Progress
- 2026-01-29: AGENTS.md created.
- 2026-01-29: Added dnSpyEx.MCP extension project with NamedPipe JSON-RPC server and MVP handlers.
- 2026-01-29: Added dnSpyEx.MCP.Bridge console project (stdio MCP -> NamedPipe).
- 2026-01-29: Updated dnSpy.sln to include both projects.
- 2026-01-29: Build attempt failed on this machine because .NET SDK 9 does not support net10.0-windows (NETSDK1045). Install .NET 10 SDK to build.
- 2026-01-29: Renamed AGENT-sc.md to AGENTS-SC.md for consistent naming.
- 2026-01-29: Fixed UTF8String JSON serialization and nullable MVID handling in McpRequestHandler; set bridge target to net10.0-windows.
- 2026-01-29: Build script (build.ps1 -NoMsbuild) timed out on this machine; targeted builds succeeded for dnSpyEx.MCP (net10.0-windows) and dnSpyEx.MCP.Bridge (net10.0-windows) with 0 errors.
- 2026-01-29: Changed extension assembly name to dnSpyEx.MCP.x; built dnSpyEx.MCP for net10.0-windows with 0 warnings and no errors.
- 2026-01-29: Added Output window logging for MCP server/requests; built dnSpyEx.MCP net10.0-windows with 0 warnings and no errors.
- 2026-01-29: Added DnSpyExBin-based external references for the plugin; builds succeeded for net10.0-windows.
- 2026-01-29: Added output logging and a targeted suppression for BamlTabSaver NullReferenceException; added a null-guard in BamlTabSaver.
- 2026-01-29: Bridge now connects to the pipe on first tool call (lazy connect) and resets the pipe on failures to avoid early "Pipe hasn't been connected yet" exits.
- 2026-01-29: Added pipe read/write error logging on the plugin side and a one-time reconnect retry in the bridge to mitigate transient broken-pipe errors.
- 2026-01-29: Plugin build auto-copies dnSpyEx.MCP.x.dll into D:\逆向\工具-逆向\dnspyEx\bin\Extensions by default (override DnSpyExInstallDir if needed).
- 2026-01-29: Added explicit NamedPipe security (current user) and server-side creation error handling; removed mandatory label to avoid privilege errors and fixed a shutdown crash from TimeSpan.FromSeconds(long).
- 2026-01-29: Server now accepts multiple concurrent NamedPipe clients (max instances) and handles connections in parallel to avoid timeouts when a stale client holds the only slot.
- 2026-01-29: Added detailed pipe I/O logging (per-client request/EOF/errors) to diagnose early disconnects causing "Pipe closed" in the bridge.
- 2026-01-29: Added opt-in bridge file logging (DNSPYEX_MCP_BRIDGE_LOG) to trace stdio and pipe operations without polluting MCP stdout.
- 2026-01-29: Added handler lifecycle logging and exception capture around per-client pipe tasks to surface immediate disconnect causes.
- 2026-01-29: Replaced JToken.ToString(Formatting) usage with JsonConvert.SerializeObject to avoid Newtonsoft.Json version mismatch crashes in dnSpyEx runtime.
- 2026-01-29: Added PipeAccessRights.CreateNewInstance to pipe security so additional server instances can be created without access denied spam.
- 2026-01-29: Allowed empty namespace parameter for listTypes/decompile namespace, and added a dnspy.help tool with usage tips exposed via tools/list.
- 2026-01-29: Added dnspy.exampleFlow tool with full usage examples and updated tool descriptions to prompt calling it first.
- 2026-01-29: Expanded dnspy.exampleFlow to include dnspy.help and documentation tool guidance.
- 2026-01-29: Added dnspy.exampleFlow coverage for all tools, new method/field/type info tools, and dnspy.search with full dnSpyEx search settings.
- 2026-01-29: Reworked dnspy.search to use a custom dnlib-based search (metadata + IL/body text) instead of internal dnSpy search APIs; updated module keying and UTF8String handling for search results.
- 2026-01-30: Migrated MCP extension + bridge into a standalone repo and switched the plugin to net10.0-windows with dnSpyEx binary references (DnSpyExBin).
- 2026-01-30: Added dnSpyEx.MCP.slnx, simplified DnSpyCommon.props (removed build task import), and pinned standalone builds to dnSpyExBin references; added .gitignore for bridge logs.
- 2026-01-30: Cleaned standalone repo layout (kept Extensions\dnSpyEx.MCP) and removed tracked build artifacts; expanded .gitignore to cover bin/obj.
- 2026-01-30: Added standalone README (build/run + binary dependency notes) and removed remotes from the legacy dnSpyEx.MCP fork to avoid confusion.
- 2026-01-30: Added MCP resources support in the bridge (resources/list, resources/read) with embedded BepInEx documentation.
- 2026-01-30: Added dnSpyEx MCP resource index document (dnspyex://docs/resource-index) to guide AI clients.
- 2026-01-30: Removed legacy bridge files from Tools root so the bridge lives only under Tools\dnSpyEx.MCP.Bridge.

## Next Steps
- Build the solution and confirm both projects compile.
- Launch dnSpyEx with the extension and verify NamedPipe server starts on AppLoaded.
- Run the bridge and test MCP calls: listAssemblies / listNamespaces / listTypes / listMembers / decompile / getSelectedText.

## Build & Usage Guide

### Prerequisites
- .NET SDK 10.x (required because the repo targets net10.0-windows).
- dnSpyEx binaries available locally (set DnSpyExBin if not in the default path).

### Build
```
dotnet build Extensions\dnSpyEx.MCP\dnSpyEx.MCP.csproj -c Release -f net10.0-windows
```

```
dotnet build Tools\dnSpyEx.MCP.Bridge\dnSpyEx.MCP.Bridge.csproj -c Release -f net10.0-windows
```

Note:
- Requires dnSpyEx binaries. Set DnSpyExBin if your dnSpyEx install path differs.
### Run dnSpyEx + MCP bridge
1) Start dnSpyEx (installed net10 build):
```
D:\逆向\工具-逆向\dnspyEx\bin\dnSpy.exe
```

2) Start the MCP bridge:
```
dotnet run --project Tools/dnSpyEx.MCP.Bridge -c Release
```

### Pipe configuration
- Default pipe name: `dnSpyEx.MCP`
- Override via env var: `DNSPYEX_MCP_PIPE`
- Or bridge arg: `--pipe <name>`

### Available MCP tools (MVP)
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

### Connect to an AI IDE (MCP-capable)
General idea: configure the IDE to launch the bridge as a stdio MCP server. Example generic config:

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

Workflow:
1) Launch dnSpyEx first (plugin starts pipe on AppLoaded).
2) Start the IDE MCP server (bridge connects to the pipe).
3) Use tools from the IDE's MCP tool list.

## Notes
- User wants progress tracked in AGENTS.md on each update.
- User confirms only .NET 10 builds; build commands should keep auto-copy enabled (do not set DisableDnSpyExInstallCopy).
- Working directory: D:\Projects\dnSpyEx.MCP.Standalone
- Reference source directory (read-only): D:\Projects\dnSpyEx.MCP

## Rules
- After each change, confirm build succeeds with no errors, then git commit and push to the repo.
- After each code change, update project progress in AGENTS.md.
- Whenever AGENTS.md is changed, mirror the corresponding Chinese updates into AGENTS-SC.md (rule block itself excluded).
- Each time a new MCP tool is added, update dnspy.exampleFlow with that tool's usage and example.
