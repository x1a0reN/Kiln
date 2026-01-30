# AGENTS

## Background
- Goal: build Kiln, a Windows-only MCP server that orchestrates game reverse engineering workflows (starting with Unity IL2CPP).
- Repo: <repo-root>

## Target Architecture
- Single stdio MCP server (no external plugin dependency).
- Internal workflow engine with job management.
- Plugin-style modules for Unity IL2CPP, IDA headless automation, .NET analysis, and packaging.

## Project Structure
- Kiln.Mcp/Kiln.Mcp.csproj: MCP stdio server (entrypoint).
- Kiln.Mcp/McpServer.cs: MCP JSON-RPC (initialize/tools/resources) + tool dispatch.
- Kiln.Mcp/ToolCatalog.cs: MCP tool definitions and input schemas.
- Kiln.Mcp/ResourceCatalog.cs: Embedded resources (BepInEx docs) + resources/list/read.
- Kiln.Core/Kiln.Core.csproj: Workflow + Job models (core).
- Kiln.Plugins/Unity.Il2Cpp: Unity IL2CPP pipeline module (planned).
- Kiln.Plugins/Ida.Pro: IDA headless automation module (planned).
- Kiln.Plugins/DotNetAnalysis: .NET analysis module (planned).
- Kiln.Plugins/Packaging: Packaging + manifests module (planned).
- Kiln.slnx: Solution containing all Kiln projects.

## Decisions
- Windows-only target for v0.1.
- stdio MCP first; streamable HTTP later.
- Unity IL2CPP vertical slice before multi-engine expansion.

## Current Progress
- 2026-01-29: AGENTS.md created.
- 2026-01-29: Added dnSpyEx MCP extension + bridge (legacy stage).
- 2026-01-30: Added MCP resources support (resources/list/read) with embedded BepInEx docs.
- 2026-01-30: Added Kiln v0.1 plan and task checklist (PLAN.md, TASK.md).
- 2026-01-30: Phase 0 kickoff — renamed project to Kiln, removed dnSpyEx plugin, created Kiln.Mcp/Kiln.Core/Kiln.Plugins structure, rewrote README and MCP tool list, added kiln.config.template.json and updated .gitignore.
- 2026-01-30: Phase 1 complete — added KilnConfig loader, JobManager with job.json persistence, job logs, and workflow.run/status/logs/cancel MCP handlers (stub workflow runner).

## Next Steps
- Implement Phase 1: Job state machine, persistence, and workflow.* MCP endpoints.
- Implement Phase 2: unity_locate + il2cpp_dump (Il2CppDumper integration).
- Implement Phase 3/4: IDA headless analysis + symbol/pseudocode export.

## Build & Usage Guide

### Prerequisites
- .NET SDK 10.x

### Build
```
dotnet build Kiln.slnx -c Release
```

### Run (stdio MCP)
```
dotnet run --project Kiln.Mcp -c Release
```

## Notes
- User wants progress tracked in AGENTS.md on each update.
- User confirms only .NET 10 builds.
- Local config file (ignored): kiln.config.json

## Rules
- After each change, confirm build succeeds with no errors, then git commit and push to the repo.
- After each code change, update project progress in AGENTS.md.
- Whenever AGENTS.md is changed, mirror the corresponding Chinese updates into AGENTS-SC.md (rule block itself excluded).
- Each time a new MCP tool is added, update kiln.exampleFlow with usage and examples.
- All work happens on feature branches; the user opens PRs and performs the final merge.
