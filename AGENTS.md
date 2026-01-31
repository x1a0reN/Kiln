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
- 2026-01-30: Phase 2 complete — added Unity IL2CPP locate + Il2CppDumper runner, and wired detect_engine/unity_locate/il2cpp_dump MCP handlers (configurable dumper path).
- 2026-01-30: Phase 2 verified — repo cleanup and Release build succeeded.
- 2026-01-30: Phase 2 hardening — safe Unity file enumeration and async Il2CppDumper output reads.
- 2026-01-30: Phase 2 security — restrict il2cpp_dump to configured Il2CppDumper executable.
- 2026-01-30: Phase 3 kickoff — ida_analyze job runner with IDA headless execution, idb/log output, optional script hook.
- 2026-01-30: Phase 3 symbols — auto-load Il2CppDumper symbols/types after IDA analysis via wrapper script.
- 2026-01-30: Phase 3 config — publish-friendly defaults and relative path resolution for dump/ida outputs.
- 2026-01-30: Phase 3 fixes — robust IDA -S argument handling and dump directory consistency checks.
- 2026-01-30: Phase 3 config — consolidate Il2CppDumper paths into il2cppRootDir and auto per-game dump dirs.
- 2026-01-30: Phase 4 export — ida_export_symbols and ida_export_pseudocode emit JSON artifacts.
- 2026-01-30: Phase 4 analysis — added analysis.* tools for indexed symbol/pseudocode search and retrieval.
- 2026-01-30: Phase 5 complete — patch_codegen template + package_mod zip/manifest/rollback output.
- 2026-01-30: Phase 5 fix — zip packaging now uses temp file to avoid self-inclusion.
- 2026-01-30: Phase 3/4 enhancement — ida_analyze can reuse existing .i64/.idb to skip analysis.
- 2026-01-30: Phase 3/4 fix — reuseExisting now requires matching database for the current game.
- 2026-01-30: Phase 3/4 fix — default IDA output now namespaces by game to avoid DB collisions.
- 2026-01-30: Phase 3/4 fix — reuseExisting validated via per-DB meta (game path + size + timestamp).
- 2026-01-30: Phase 3/4 fix — reuseExisting also validates script.json and il2cpp.h metadata.
- 2026-01-30: Phase 4/5 enhancements — export call graph + strings, add analysis xrefs/strings search + cross-job index cache, and enrich patch_codegen with targets + IL2CPP hook template.
- 2026-01-30: Phase 3/4 enhancement — ida_register_db imports external .i64/.idb and writes Kiln metadata for reuse.
- 2026-01-30: Deployment — MCP resolves plugin DLLs from publish/Plugins folder for cleaner release layout.
- 2026-01-30: Phase 5 fix — patch_codegen now escapes control characters in generated C# strings.
- 2026-01-30: Repo hygiene — ignore publish/ output in .gitignore.
- 2026-01-30: Docs — expanded kiln.exampleFlow with per-tool purpose + notes.
- 2026-01-30: Docs — added best practices/common errors/recommended order and enforced exampleFlow read-before-use.
- 2026-01-30: Release — added scripts/publish.ps1 to build and normalize publish/Kiln layout.
- 2026-01-30: IDA 9.2 support — handle idat.exe/ida.exe naming and update config/example path.
- 2026-01-30: Release fix — resolve IDA export scripts from publish root or Plugins folder.
- 2026-01-30: IDA export fix — skip -o when opening existing .i64/.idb to avoid export failures.
- 2026-01-30: IDA CLI fix — pass -S script args in a single quoted string so IDA receives parameters.
- 2026-01-30: IDA CLI fix — pass script args as separate arguments after -S<script> to ensure ARGV is populated.
- 2026-01-30: IDA CLI fix — build Arguments string with -S<quoted script> <quoted args> to mirror manual invocation.
- 2026-01-30: IDA CLI fix — wrap -S invocation in a single quoted string so script args stay attached.
- 2026-01-30: IDA CLI fix — -S uses quoted script/args in Arguments string (no extra escaping).
- 2026-01-30: IDA CLI fix — always quote -S script/args to avoid missing ARGV.

- 2026-01-31: IDA CLI fix — use Windows-safe command-line quoting for -S to keep script args attached.
- 2026-01-31: IDA scripts use env fallback for export/auto-load args to avoid -S parsing issues.
- 2026-01-31: IDA export compat — fall back to ida_ida.inf_get_* when get_inf_structure is unavailable.
- 2026-01-31: IDA export fix — clean stale unpacked DB files before headless export to avoid lock prompts.
- 2026-01-31: Analysis pseudocode on-demand export + auto-export search/get + optional background full export.
- 2026-01-31: patch_codegen resolves relative artifacts via jobId/gameDir/analysisDir and auto-falls back to analysis outputs.
## Next Steps
- Implement Phase 3: IDA headless analysis + symbol/typing load.
- Implement Phase 4: symbol and pseudocode export.
- Implement Phase 5: patch/codegen + packaging output.

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
