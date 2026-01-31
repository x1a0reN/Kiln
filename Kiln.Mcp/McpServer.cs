using System;
using System.IO;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Kiln.Core;
using Kiln.Plugins.Ida.Pro;
using Kiln.Plugins.Packaging;
using Kiln.Plugins.Unity.Il2Cpp;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kiln.Mcp {
	sealed class McpServer {
		readonly ToolCatalog catalog;
		readonly ResourceCatalog resources;
		readonly JobManager jobManager;
		readonly KilnConfig config;

		public McpServer(JobManager jobManager, KilnConfig config) {
			this.jobManager = jobManager ?? throw new ArgumentNullException(nameof(jobManager));
			this.config = config ?? throw new ArgumentNullException(nameof(config));
			catalog = new ToolCatalog();
			resources = new ResourceCatalog();
		}

		public async Task RunAsync(CancellationToken token) {
			while (!token.IsCancellationRequested) {
				var line = await Console.In.ReadLineAsync().ConfigureAwait(false);
				if (line is null)
					break;
				if (string.IsNullOrWhiteSpace(line))
					continue;

				JObject request;
				try {
					request = JObject.Parse(line);
				}
				catch (JsonException) {
				KilnLog.Warn("stdio parse error");
				await WriteResponseAsync(MakeError(null, -32700, "Parse error")).ConfigureAwait(false);
				continue;
			}

			KilnLog.Info($"stdio request: {request["method"]?.Value<string>() ?? "(null)"}");
			var response = await HandleRequestAsync(request, token).ConfigureAwait(false);
			if (response is null)
				continue;
			await WriteResponseAsync(response).ConfigureAwait(false);
			}
		}

		async Task<JObject?> HandleRequestAsync(JObject request, CancellationToken token) {
			var id = request["id"];
			var method = request["method"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(method))
				return MakeError(id, -32600, "Invalid Request");

			if (method == "initialize")
				return Initialize(request, id);
			if (method == "tools/list")
				return ToolsList(id);
			if (method == "tools/call")
				return await ToolsCallAsync(request, id, token).ConfigureAwait(false);
			if (method == "resources/list")
				return ResourcesList(id);
			if (method == "resources/read")
				return ResourcesRead(request, id);
			if (method == "notifications/initialized")
				return null;

			return MakeError(id, -32601, $"Method not found: {method}");
		}

		JObject Initialize(JObject request, JToken? id) {
			var protocolVersion = request["params"]?["protocolVersion"]?.Value<string>() ?? "2024-11-05";
			var result = new JObject {
				["protocolVersion"] = protocolVersion,
				["capabilities"] = new JObject {
					["tools"] = new JObject(),
					["resources"] = new JObject(),
				},
				["serverInfo"] = new JObject {
					["name"] = "Kiln.Mcp",
					["version"] = "0.1.0",
				},
			};
			return MakeResult(id, result);
		}

		JObject ToolsList(JToken? id) {
			var tools = catalog.Tools.Values
				.Select(tool => new JObject {
					["name"] = tool.Name,
					["description"] = tool.Description,
					["inputSchema"] = tool.InputSchema,
				});
			return MakeResult(id, new JObject { ["tools"] = new JArray(tools) });
		}

		JObject ResourcesList(JToken? id) {
			var list = resources.GetResources()
				.Select(resource => new JObject {
					["uri"] = resource.Uri,
					["name"] = resource.Name,
					["description"] = resource.Description,
					["mimeType"] = resource.MimeType,
				});
			return MakeResult(id, new JObject { ["resources"] = new JArray(list) });
		}

		JObject ResourcesRead(JObject request, JToken? id) {
			var args = request["params"] as JObject;
			var uri = args?["uri"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(uri))
				return MakeError(id, -32602, "Missing resource uri");

			var content = resources.ReadResource(uri);
			if (content is null)
				return MakeError(id, -32602, $"Unknown resource: {uri}");

			return MakeResult(id, new JObject {
				["contents"] = new JArray {
					new JObject {
						["uri"] = uri,
						["mimeType"] = "text/markdown",
						["text"] = content,
					},
				},
			});
		}

		async Task<JObject> ToolsCallAsync(JObject request, JToken? id, CancellationToken token) {
			var args = request["params"] as JObject;
			var name = args?["name"]?.Value<string>();
			var input = args?["arguments"] as JObject ?? new JObject();
			if (string.IsNullOrWhiteSpace(name))
				return MakeError(id, -32602, "Missing tool name");

			if (!catalog.Tools.TryGetValue(name, out var tool))
				return MakeError(id, -32601, $"Unknown tool: {name}");

			KilnLog.Info($"tool call: {name}");
			if (tool.Method == "__local.help") {
				return MakeResult(id, new JObject {
					["content"] = new JArray {
						new JObject {
							["type"] = "text",
							["text"] = HelpText,
						},
					},
					["isError"] = false,
				});
			}
			if (tool.Method == "__local.exampleFlow") {
				return MakeResult(id, new JObject {
					["content"] = new JArray {
						new JObject {
							["type"] = "text",
							["text"] = ExampleFlowText,
						},
					},
					["isError"] = false,
				});
			}

			if (tool.Method == "workflow.run")
				return HandleWorkflowRun(id, input);
			if (tool.Method == "workflow.status")
				return HandleWorkflowStatus(id, input);
			if (tool.Method == "workflow.logs")
				return HandleWorkflowLogs(id, input);
			if (tool.Method == "workflow.cancel")
				return HandleWorkflowCancel(id, input);
			if (tool.Method == "detect_engine")
				return HandleDetectEngine(id, input);
			if (tool.Method == "unity_locate")
				return HandleUnityLocate(id, input);
			if (tool.Method == "il2cpp_dump")
				return HandleIl2CppDump(id, input);
			if (tool.Method == "ida_analyze")
				return HandleIdaAnalyze(id, input);
			if (tool.Method == "ida_register_db")
				return HandleIdaRegisterDb(id, input);
			if (tool.Method == "ida_export_symbols")
				return HandleIdaExportSymbols(id, input);
			if (tool.Method == "ida_export_pseudocode")
				return HandleIdaExportPseudocode(id, input);
			if (tool.Method == "analysis.index.build")
				return HandleAnalysisIndexBuild(id, input);
			if (tool.Method == "analysis.symbols.search")
				return HandleAnalysisSymbolsSearch(id, input);
			if (tool.Method == "analysis.symbols.get")
				return HandleAnalysisSymbolsGet(id, input);
			if (tool.Method == "analysis.symbols.xrefs")
				return HandleAnalysisSymbolsXrefs(id, input);
			if (tool.Method == "analysis.strings.search")
				return HandleAnalysisStringsSearch(id, input);
			if (tool.Method == "analysis.pseudocode.search")
				return HandleAnalysisPseudocodeSearch(id, input);
			if (tool.Method == "analysis.pseudocode.get")
				return HandleAnalysisPseudocodeGet(id, input);
			if (tool.Method == "patch_codegen")
				return HandlePatchCodegen(id, input);
			if (tool.Method == "package_mod")
				return HandlePackageMod(id, input);

			await Task.Yield();
			return ToolError(id, $"Tool not implemented yet: {tool.Name}");
		}

		JObject HandleWorkflowRun(JToken? id, JObject input) {
			var flowName = input["flowName"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(flowName))
				return ToolError(id, "Missing flowName");

			var parameters = input["params"] as JObject;
			var paramsJson = parameters?.ToString(Formatting.None) ?? "{}";

			var job = jobManager.StartWorkflow(flowName, paramsJson);
			var payload = new JObject {
				["jobId"] = job.JobId,
				["state"] = job.State.ToString(),
				["stage"] = job.Stage,
				["percent"] = job.Percent,
			};
			return ToolOk(id, payload);
		}

		JObject HandleWorkflowStatus(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");

			if (!jobManager.TryGetStatus(jobId, out var info))
				return ToolError(id, $"Unknown job: {jobId}");

			var payload = new JObject {
				["jobId"] = info.JobId,
				["state"] = info.State.ToString(),
				["stage"] = info.Stage,
				["percent"] = info.Percent,
			};
			return ToolOk(id, payload);
		}

		JObject HandleWorkflowLogs(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");

			var tail = input["tail"]?.Value<int?>() ?? 200;
			if (!jobManager.TryReadLogs(jobId, tail, out var logs))
				return ToolError(id, $"Unknown job: {jobId}");

			return ToolOk(id, logs);
		}

		JObject HandleWorkflowCancel(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");

			if (!jobManager.TryCancel(jobId, out var info))
				return ToolError(id, $"Unknown job: {jobId}");

			var payload = new JObject {
				["jobId"] = info.JobId,
				["state"] = info.State.ToString(),
				["stage"] = info.Stage,
				["percent"] = info.Percent,
			};
			return ToolOk(id, payload);
		}

		JObject HandleDetectEngine(JToken? id, JObject input) {
			var gameDir = input["gameDir"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(gameDir))
				return ToolError(id, "Missing gameDir");

			var locate = UnityLocator.Locate(gameDir);
			var engine = locate.IsIl2Cpp || locate.IsMono ? "Unity" : "Unknown";
			var runtime = locate.IsIl2Cpp ? "IL2CPP" : (locate.IsMono ? "Mono" : "Unknown");

			var payload = new JObject {
				["engine"] = engine,
				["runtime"] = runtime,
				["gameDir"] = locate.GameDir,
				["gameAssemblyPath"] = locate.GameAssemblyPath,
				["metadataPath"] = locate.MetadataPath,
				["dataDir"] = locate.DataDir,
				["managedDir"] = locate.ManagedDir,
				["notes"] = locate.Notes,
			};

			return ToolOk(id, payload);
		}

		JObject HandleUnityLocate(JToken? id, JObject input) {
			var gameDir = input["gameDir"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(gameDir))
				return ToolError(id, "Missing gameDir");

			var locate = UnityLocator.Locate(gameDir);
			var payload = new JObject {
				["gameDir"] = locate.GameDir,
				["gameAssemblyPath"] = locate.GameAssemblyPath,
				["metadataPath"] = locate.MetadataPath,
				["dataDir"] = locate.DataDir,
				["managedDir"] = locate.ManagedDir,
				["isIl2Cpp"] = locate.IsIl2Cpp,
				["isMono"] = locate.IsMono,
				["notes"] = locate.Notes,
			};

			return ToolOk(id, payload);
		}

		JObject HandleIl2CppDump(JToken? id, JObject input) {
			var gameDir = input["gameDir"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(gameDir))
				return ToolError(id, "Missing gameDir");

			var outputDir = input["outputDir"]?.Value<string>();
			var expectedDumpDir = config.GetIl2CppDumpDir(gameDir);
			if (string.IsNullOrWhiteSpace(outputDir))
				outputDir = expectedDumpDir;
			if (!PathsEqual(outputDir, expectedDumpDir))
				return ToolError(id, "outputDir must match il2cppRootDir/<game-name> in kiln.config.json.");

			var dumperPath = input["dumperPath"]?.Value<string>();
			var expectedDumperDir = config.Il2CppRootDir;
			var expectedDumperExe = config.GetIl2CppDumperPath();
			if (!string.IsNullOrWhiteSpace(dumperPath)) {
				if (string.IsNullOrWhiteSpace(expectedDumperDir))
					return ToolError(id, "dumperPath override is not allowed; set kiln.config.json (il2cppRootDir).");
				if (!PathsEqual(dumperPath, expectedDumperDir) && !PathsEqual(dumperPath, expectedDumperExe))
					return ToolError(id, "dumperPath override is not allowed; use il2cppRootDir or Il2CppDumper.exe inside it.");
			}
			dumperPath = expectedDumperDir;

			if (string.IsNullOrWhiteSpace(dumperPath))
				return ToolError(id, "Missing dumperPath (set il2cppRootDir in kiln.config.json)");

			var locate = UnityLocator.Locate(gameDir);
			if (!locate.IsIl2Cpp || string.IsNullOrWhiteSpace(locate.GameAssemblyPath) || string.IsNullOrWhiteSpace(locate.MetadataPath))
				return ToolError(id, "Unity IL2CPP artifacts not found (GameAssembly.dll / global-metadata.dat).");

			Il2CppDumpResult result;
			try {
				result = Il2CppDumperRunner.Run(locate.GameAssemblyPath, locate.MetadataPath, dumperPath, outputDir);
			}
			catch (Exception ex) {
				return ToolError(id, $"Il2CppDumper failed: {ex.Message}");
			}

			var payload = new JObject {
				["success"] = result.Success,
				["exitCode"] = result.ExitCode,
				["gameAssemblyPath"] = result.GameAssemblyPath,
				["metadataPath"] = result.MetadataPath,
				["outputDir"] = result.OutputDir,
				["stdout"] = result.StdOut,
				["stderr"] = result.StdErr,
			};

			return ToolOk(id, payload);
		}

		JObject HandleIdaAnalyze(JToken? id, JObject input) {
			var gameDir = input["gameDir"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(gameDir))
				return ToolError(id, "Missing gameDir");

			var idaPath = input["idaPath"]?.Value<string>();
			if (!string.IsNullOrWhiteSpace(idaPath)) {
				if (string.IsNullOrWhiteSpace(config.IdaPath))
					return ToolError(id, "idaPath override is not allowed; set kiln.config.json (idaPath).");
				if (!PathsEqual(idaPath, config.IdaPath))
					return ToolError(id, "idaPath override is not allowed; use the configured idaPath.");
			}

			idaPath = config.IdaPath;
			if (string.IsNullOrWhiteSpace(idaPath))
				return ToolError(id, "Missing idaPath (and no default in kiln.config.json)");
			if (!File.Exists(idaPath))
				return ToolError(id, $"idaPath not found: {idaPath}");

			var idbDir = input["idbDir"]?.Value<string>();
			var idbDirProvided = !string.IsNullOrWhiteSpace(idbDir);
			if (!idbDirProvided)
				idbDir = config.IdaOutputDir;
			if (string.IsNullOrWhiteSpace(idbDir))
				return ToolError(id, "Missing idbDir (set idaOutputDir in kiln.config.json).");
			if (!idbDirProvided)
				idbDir = config.GetIdaOutputDirForGame(gameDir);

			input["idbDir"] = idbDir;

			var reuseExisting = input["reuseExisting"]?.Value<bool?>() ?? true;

			var locate = UnityLocator.Locate(gameDir);
			var expectedDb = string.Empty;
			if (!string.IsNullOrWhiteSpace(locate.GameAssemblyPath))
				expectedDb = IdaHeadlessRunner.GetDatabasePath(idaPath, locate.GameAssemblyPath, idbDir);

			var scriptPath = input["scriptPath"]?.Value<string>();
			if (!string.IsNullOrWhiteSpace(scriptPath)) {
				var expectedScriptPath = config.GetIdaSymbolsScriptPath();
				if (string.IsNullOrWhiteSpace(expectedScriptPath))
					return ToolError(id, "scriptPath override is not allowed; set kiln.config.json (il2cppRootDir).");
				if (!PathsEqual(scriptPath, expectedScriptPath))
					return ToolError(id, "scriptPath override is not allowed; use ida_with_struct_py3.py inside il2cppRootDir.");
			}

			var symbolScriptPath = config.GetIdaSymbolsScriptPath();
			if (string.IsNullOrWhiteSpace(symbolScriptPath))
				return ToolError(id, "Missing ida_with_struct_py3.py (set il2cppRootDir in kiln.config.json).");
			if (!File.Exists(symbolScriptPath))
				return ToolError(id, $"ida_with_struct_py3.py not found: {symbolScriptPath}");

			var dumpDir = config.GetIl2CppDumpDir(gameDir);
			var scriptJson = Path.Combine(dumpDir, "script.json");
			var il2cppHeader = Path.Combine(dumpDir, "il2cpp.h");
			if (!File.Exists(scriptJson))
				return ToolError(id, $"script.json not found in il2cpp dump dir: {scriptJson}");
			if (!File.Exists(il2cppHeader))
				return ToolError(id, $"il2cpp.h not found in il2cpp dump dir: {il2cppHeader}");

			var existingDb = !string.IsNullOrWhiteSpace(expectedDb) && File.Exists(expectedDb) && MetaMatchesExpectedDb(expectedDb, locate, scriptJson, il2cppHeader)
				? expectedDb
				: null;

			if (reuseExisting && !string.IsNullOrWhiteSpace(existingDb)) {
				var reuseParamsJson = input.ToString(Formatting.None);
				var reuseJob = jobManager.StartJob("ida.analyze", reuseParamsJson, context => {
					context.Update(JobState.Running, "reuse_existing", 10, null);
					context.Log($"Existing IDA database found, skipping analysis: {existingDb}");
					context.Update(JobState.Completed, "completed", 100, null);
					return Task.CompletedTask;
				});

				var reusePayload = new JObject {
					["jobId"] = reuseJob.JobId,
					["state"] = reuseJob.State.ToString(),
					["stage"] = reuseJob.Stage,
					["percent"] = reuseJob.Percent,
					["databasePath"] = existingDb,
				};
				return ToolOk(id, reusePayload);
			}

			var autoLoadScript = IdaHeadlessRunner.GetAutoLoadScriptPath();
			if (!File.Exists(autoLoadScript))
				return ToolError(id, $"Auto-load script not found: {autoLoadScript}");

			if (!locate.IsIl2Cpp || string.IsNullOrWhiteSpace(locate.GameAssemblyPath))
				return ToolError(id, "Unity IL2CPP GameAssembly.dll not found.");

			var paramsJson = input.ToString(Formatting.None);
			var job = jobManager.StartJob("ida.analyze", paramsJson, async context => {
				context.Update(JobState.Running, "ida_analyze", 5, null);
				context.Log($"IDA analysis started. Target: {locate.GameAssemblyPath}");

				IdaAnalyzeResult result;
				try {
					result = await IdaHeadlessRunner.RunAsync(
						idaPath,
						locate.GameAssemblyPath,
						idbDir,
						autoLoadScript,
						new[] { symbolScriptPath, scriptJson, il2cppHeader },
						context.Token,
						context.Log).ConfigureAwait(false);
				}
				catch (OperationCanceledException) {
					return;
				}

				if (result.Success) {
					context.Log($"IDA analysis completed. Database: {result.DatabasePath}");
					TryWriteDbMeta(result.DatabasePath, locate, scriptJson, il2cppHeader);
					context.Update(JobState.Completed, "completed", 100, null);
				}
				else {
					context.Log($"IDA analysis failed. ExitCode={result.ExitCode}");
					context.Update(JobState.Failed, "failed", 100, $"IDA exited with code {result.ExitCode}");
				}
			});

			var payload = new JObject {
				["jobId"] = job.JobId,
				["state"] = job.State.ToString(),
				["stage"] = job.Stage,
				["percent"] = job.Percent,
				["databasePath"] = expectedDb,
			};
			return ToolOk(id, payload);
		}

		JObject HandleIdaRegisterDb(JToken? id, JObject input) {
			var gameDir = input["gameDir"]?.Value<string>();
			var databasePath = input["databasePath"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(gameDir))
				return ToolError(id, "Missing gameDir");
			if (string.IsNullOrWhiteSpace(databasePath))
				return ToolError(id, "Missing databasePath");

			if (!File.Exists(databasePath))
				return ToolError(id, $"databasePath not found: {databasePath}");

			var ext = Path.GetExtension(databasePath);
			if (!ext.Equals(".i64", StringComparison.OrdinalIgnoreCase) && !ext.Equals(".idb", StringComparison.OrdinalIgnoreCase))
				return ToolError(id, "databasePath must be a .i64 or .idb file.");

			var locate = UnityLocator.Locate(gameDir);
			if (!locate.IsIl2Cpp || string.IsNullOrWhiteSpace(locate.GameAssemblyPath))
				return ToolError(id, "Unity IL2CPP GameAssembly.dll not found.");

			var dumpDir = config.GetIl2CppDumpDir(gameDir);
			var scriptJson = Path.Combine(dumpDir, "script.json");
			var il2cppHeader = Path.Combine(dumpDir, "il2cpp.h");
			if (!File.Exists(scriptJson))
				return ToolError(id, $"script.json not found in il2cpp dump dir: {scriptJson}");
			if (!File.Exists(il2cppHeader))
				return ToolError(id, $"il2cpp.h not found in il2cpp dump dir: {il2cppHeader}");

			var idbDir = input["idbDir"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(idbDir))
				idbDir = config.GetIdaOutputDirForGame(gameDir);
			Directory.CreateDirectory(idbDir);

			var copyToIdbDir = input["copyToIdbDir"]?.Value<bool?>() ?? true;
			var overwrite = input["overwrite"]?.Value<bool?>() ?? false;

			var expectedDb = GetExpectedDatabasePathForImport(idbDir, locate.GameAssemblyPath, databasePath);
			var targetDb = databasePath;
			var copied = false;

			if (copyToIdbDir && !PathsEqual(databasePath, expectedDb)) {
				if (File.Exists(expectedDb) && !overwrite)
					return ToolError(id, $"Target DB already exists: {expectedDb} (set overwrite=true to replace).");
				File.Copy(databasePath, expectedDb, overwrite);
				targetDb = expectedDb;
				copied = true;
			}

			TryWriteDbMeta(targetDb, locate, scriptJson, il2cppHeader);
			var payload = new JObject {
				["databasePath"] = targetDb,
				["copied"] = copied,
				["metaPath"] = GetDbMetaPath(targetDb),
			};
			return ToolOk(id, payload);
		}

		string GetExpectedDatabasePathForImport(string idbDir, string gameAssemblyPath, string sourceDatabasePath) {
			var ext = Path.GetExtension(sourceDatabasePath);
			var name = Path.GetFileNameWithoutExtension(gameAssemblyPath);
			if (string.IsNullOrWhiteSpace(ext))
				ext = ".i64";
			return Path.Combine(idbDir, name + ext);
		}

		JObject HandleIdaExportSymbols(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");

			if (!jobManager.TryGetStatus(jobId, out _))
				return ToolError(id, $"Unknown job: {jobId}");

			var analysisDir = ResolveAnalysisDir(jobId, input);
			if (string.IsNullOrWhiteSpace(analysisDir))
				return ToolError(id, "Missing analysis directory (set idaOutputDir or run ida_analyze first).");
			Directory.CreateDirectory(analysisDir);

			var databasePath = FindIdaDatabase(analysisDir);
			if (string.IsNullOrWhiteSpace(databasePath))
				return ToolError(id, "IDA database not found (expected .i64/.idb in analysis directory).");

			var exportPath = input["outputPath"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(exportPath))
				exportPath = Path.Combine(analysisDir, "symbols.json");
			else if (!Path.IsPathRooted(exportPath))
				exportPath = Path.Combine(analysisDir, exportPath);
			var scriptPath = IdaHeadlessRunner.GetExportSymbolsScriptPath();
			if (!File.Exists(scriptPath))
				return ToolError(id, $"Export script not found: {scriptPath}");

			var result = RunIdaExport(config.IdaPath, databasePath, scriptPath, exportPath, null);
			if (!result.Success)
				return ToolError(id, $"Symbol export failed: {result.StdErr}");

			var payload = new JObject {
				["outputPath"] = exportPath,
				["databasePath"] = databasePath,
				["stdout"] = result.StdOut,
				["stderr"] = result.StdErr,
			};
			return ToolOk(id, payload);
		}

		JObject HandleIdaExportPseudocode(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");

			var nameFilter = input["nameFilter"]?.Value<string>();

			if (!jobManager.TryGetStatus(jobId, out _))
				return ToolError(id, $"Unknown job: {jobId}");

			var analysisDir = ResolveAnalysisDir(jobId, input);
			if (string.IsNullOrWhiteSpace(analysisDir))
				return ToolError(id, "Missing analysis directory (set idaOutputDir or run ida_analyze first).");
			Directory.CreateDirectory(analysisDir);

			var databasePath = FindIdaDatabase(analysisDir);
			if (string.IsNullOrWhiteSpace(databasePath))
				return ToolError(id, "IDA database not found (expected .i64/.idb in analysis directory).");

			var exportPath = input["outputPath"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(exportPath))
				exportPath = Path.Combine(analysisDir, "pseudocode.json");
			else if (!Path.IsPathRooted(exportPath))
				exportPath = Path.Combine(analysisDir, exportPath);
			var scriptPath = IdaHeadlessRunner.GetExportPseudocodeScriptPath();
			if (!File.Exists(scriptPath))
				return ToolError(id, $"Export script not found: {scriptPath}");

			var result = RunIdaExport(config.IdaPath, databasePath, scriptPath, exportPath, nameFilter);
			if (!result.Success)
				return ToolError(id, $"Pseudocode export failed: {result.StdErr}");

			var payload = new JObject {
				["outputPath"] = exportPath,
				["databasePath"] = databasePath,
				["stdout"] = result.StdOut,
				["stderr"] = result.StdErr,
			};
			return ToolOk(id, payload);
		}

		JObject HandleAnalysisIndexBuild(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");

			var analysisDir = ResolveAnalysisDir(jobId, input);
			if (string.IsNullOrWhiteSpace(analysisDir))
				return ToolError(id, "Missing analysis directory (set idaOutputDir or run ida_analyze first).");

			var symbolsPath = Path.Combine(analysisDir, "symbols.json");
			var pseudocodePath = Path.Combine(analysisDir, "pseudocode.json");
			var stringsPath = Path.Combine(analysisDir, "strings.json");
			var result = new JObject();

			if (File.Exists(symbolsPath)) {
				var symbols = LoadSymbols(symbolsPath);
				var localIndex = Path.Combine(analysisDir, "symbols.index.json");
				SaveSymbolsIndex(localIndex, symbols);
				var cacheIndex = GetIndexCachePath(symbolsPath, "symbols.index.json");
				if (!PathsEqual(localIndex, cacheIndex))
					SaveSymbolsIndex(cacheIndex, symbols);
				result["symbolsIndex"] = cacheIndex;
				result["symbolsLocalIndex"] = localIndex;
				result["symbolsCount"] = symbols.Count;
			}
			else {
				result["symbolsIndex"] = null;
			}

			if (File.Exists(pseudocodePath)) {
				var functions = LoadPseudocode(pseudocodePath);
				var localIndex = Path.Combine(analysisDir, "pseudocode.index.json");
				SavePseudocodeIndex(localIndex, functions);
				var cacheIndex = GetIndexCachePath(pseudocodePath, "pseudocode.index.json");
				if (!PathsEqual(localIndex, cacheIndex))
					SavePseudocodeIndex(cacheIndex, functions);
				result["pseudocodeIndex"] = cacheIndex;
				result["pseudocodeLocalIndex"] = localIndex;
				result["pseudocodeCount"] = functions.Count;
			}
			else {
				result["pseudocodeIndex"] = null;
			}

			if (File.Exists(stringsPath)) {
				var strings = LoadStrings(stringsPath);
				var localIndex = Path.Combine(analysisDir, "strings.index.json");
				SaveStringsIndex(localIndex, strings);
				var cacheIndex = GetIndexCachePath(stringsPath, "strings.index.json");
				if (!PathsEqual(localIndex, cacheIndex))
					SaveStringsIndex(cacheIndex, strings);
				result["stringsIndex"] = cacheIndex;
				result["stringsLocalIndex"] = localIndex;
				result["stringsCount"] = strings.Count;
			}
			else {
				result["stringsIndex"] = null;
			}

			return ToolOk(id, result);
		}

		JObject HandleAnalysisSymbolsSearch(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			var query = input["query"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");
			if (string.IsNullOrWhiteSpace(query))
				return ToolError(id, "Missing query");

			var analysisDir = ResolveAnalysisDir(jobId, input);
			if (string.IsNullOrWhiteSpace(analysisDir))
				return ToolError(id, "Missing analysis directory (set idaOutputDir or run ida_analyze first).");

			var list = LoadSymbolsPreferIndex(analysisDir);
			var field = input["field"]?.Value<string>() ?? "name";
			if (!field.Equals("name", StringComparison.OrdinalIgnoreCase)
				&& !field.Equals("signature", StringComparison.OrdinalIgnoreCase)
				&& !field.Equals("ea", StringComparison.OrdinalIgnoreCase)) {
				return ToolError(id, "Invalid field (use name|signature|ea).");
			}
			var match = input["match"]?.Value<string>() ?? "contains";
			var caseSensitive = input["caseSensitive"]?.Value<bool?>() ?? false;
			var limit = Math.Clamp(input["limit"]?.Value<int?>() ?? 20, 1, 200);
			var offset = Math.Max(0, input["offset"]?.Value<int?>() ?? 0);
			var fields = input["fields"] as JArray;

			string queryNorm = caseSensitive ? query! : query!.ToLowerInvariant();
			var results = new List<JObject>();
			var total = 0;

			var queryEa = NormalizeEa(queryNorm);
			for (var i = 0; i < list.Count; i++) {
				var entry = list[i];
				if (!SymbolMatches(entry, field, match, caseSensitive, queryNorm, queryEa))
					continue;

				total++;
				if (total <= offset)
					continue;
				if (results.Count >= limit)
					continue;

				results.Add(SelectSymbolFields(entry, fields));
			}

			var payload = new JObject {
				["count"] = results.Count,
				["total"] = total,
				["matches"] = new JArray(results),
			};
			return ToolOk(id, payload);
		}

		JObject HandleAnalysisSymbolsGet(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");

			var name = input["name"]?.Value<string>();
			var ea = input["ea"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(ea))
				return ToolError(id, "Missing name or ea");

			var analysisDir = ResolveAnalysisDir(jobId, input);
			if (string.IsNullOrWhiteSpace(analysisDir))
				return ToolError(id, "Missing analysis directory (set idaOutputDir or run ida_analyze first).");

			var list = LoadSymbolsPreferIndex(analysisDir);
			var caseSensitive = input["caseSensitive"]?.Value<bool?>() ?? false;
			var nameNorm = caseSensitive ? name : name?.ToLowerInvariant();

			foreach (var entry in list) {
				if (!string.IsNullOrWhiteSpace(name)) {
					var entryName = entry.Name ?? string.Empty;
					var entryNorm = caseSensitive ? entryName : (entry.NameLower ?? entryName.ToLowerInvariant());
					if (entryNorm == nameNorm)
						return ToolOk(id, SelectSymbolFields(entry, null));
				}
				else if (!string.IsNullOrWhiteSpace(ea)) {
					var entryEa = NormalizeEa(entry.Ea);
					var targetEa = NormalizeEa(ea);
					if (entryEa == targetEa)
						return ToolOk(id, SelectSymbolFields(entry, null));
				}
			}

			return ToolError(id, "Symbol not found.");
		}

		JObject HandleAnalysisSymbolsXrefs(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");

			var name = input["name"]?.Value<string>();
			var ea = input["ea"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(ea))
				return ToolError(id, "Missing name or ea");

			var direction = input["direction"]?.Value<string>() ?? "both";
			if (!direction.Equals("callers", StringComparison.OrdinalIgnoreCase)
				&& !direction.Equals("callees", StringComparison.OrdinalIgnoreCase)
				&& !direction.Equals("both", StringComparison.OrdinalIgnoreCase)) {
				return ToolError(id, "Invalid direction (use callers|callees|both).");
			}
			var limit = Math.Clamp(input["limit"]?.Value<int?>() ?? 50, 1, 200);
			var offset = Math.Max(0, input["offset"]?.Value<int?>() ?? 0);

			var analysisDir = ResolveAnalysisDir(jobId, input);
			if (string.IsNullOrWhiteSpace(analysisDir))
				return ToolError(id, "Missing analysis directory (set idaOutputDir or run ida_analyze first).");

			var list = LoadSymbolsPreferIndex(analysisDir);
			var map = BuildSymbolMap(list);
			var entry = FindSymbol(list, name, ea, input["caseSensitive"]?.Value<bool?>() ?? false);
			if (entry is null)
				return ToolError(id, "Symbol not found.");

			var refs = new List<string>();
			if (direction.Equals("callers", StringComparison.OrdinalIgnoreCase) || direction.Equals("both", StringComparison.OrdinalIgnoreCase))
				refs.AddRange(entry.Callers ?? new List<string>());
			if (direction.Equals("callees", StringComparison.OrdinalIgnoreCase) || direction.Equals("both", StringComparison.OrdinalIgnoreCase))
				refs.AddRange(entry.Calls ?? new List<string>());

			var normalized = refs.Select(NormalizeEa).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct().ToList();
			var results = new List<JObject>();
			var total = 0;
			foreach (var refEa in normalized) {
				total++;
				if (total <= offset)
					continue;
				if (results.Count >= limit)
					continue;

				if (map.TryGetValue(refEa, out var refEntry)) {
					results.Add(new JObject {
						["ea"] = refEntry.Ea,
						["name"] = refEntry.Name,
						["signature"] = refEntry.Signature,
					});
				}
				else {
					results.Add(new JObject {
						["ea"] = refEa,
						["name"] = null,
					});
				}
			}

			var payload = new JObject {
				["count"] = results.Count,
				["total"] = total,
				["matches"] = new JArray(results),
			};
			return ToolOk(id, payload);
		}

		JObject HandleAnalysisStringsSearch(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			var query = input["query"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");
			if (string.IsNullOrWhiteSpace(query))
				return ToolError(id, "Missing query");

			var analysisDir = ResolveAnalysisDir(jobId, input);
			if (string.IsNullOrWhiteSpace(analysisDir))
				return ToolError(id, "Missing analysis directory (set idaOutputDir or run ida_analyze first).");

			var list = LoadStringsPreferIndex(analysisDir);
			var match = input["match"]?.Value<string>() ?? "contains";
			var caseSensitive = input["caseSensitive"]?.Value<bool?>() ?? false;
			var includeRefs = input["includeRefs"]?.Value<bool?>() ?? false;
			var maxRefs = Math.Clamp(input["maxRefs"]?.Value<int?>() ?? 50, 0, 500);
			var limit = Math.Clamp(input["limit"]?.Value<int?>() ?? 20, 1, 200);
			var offset = Math.Max(0, input["offset"]?.Value<int?>() ?? 0);

			var queryNorm = caseSensitive ? query : query!.ToLowerInvariant();
			var results = new List<JObject>();
			var total = 0;

			foreach (var entry in list) {
				var value = entry.Value ?? string.Empty;
				var valueNorm = caseSensitive ? value : (entry.ValueLower ?? value.ToLowerInvariant());
				if (!IsMatch(valueNorm, queryNorm, match))
					continue;

				total++;
				if (total <= offset)
					continue;
				if (results.Count >= limit)
					continue;

				var obj = new JObject {
					["ea"] = entry.Ea,
					["value"] = entry.Value,
					["length"] = entry.Length,
					["refCount"] = entry.RefCount,
				};
				if (includeRefs && entry.Refs is not null) {
					var refs = entry.Refs.Take(maxRefs).Select(r => new JObject {
						["funcEa"] = r.FuncEa,
						["funcName"] = r.FuncName,
						["refEa"] = r.RefEa,
					});
					obj["refs"] = new JArray(refs);
				}
				results.Add(obj);
			}

			var payload = new JObject {
				["count"] = results.Count,
				["total"] = total,
				["matches"] = new JArray(results),
			};
			return ToolOk(id, payload);
		}

		JObject HandleAnalysisPseudocodeSearch(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			var query = input["query"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");
			if (string.IsNullOrWhiteSpace(query))
				return ToolError(id, "Missing query");

			var analysisDir = ResolveAnalysisDir(jobId, input);
			if (string.IsNullOrWhiteSpace(analysisDir))
				return ToolError(id, "Missing analysis directory (set idaOutputDir or run ida_analyze first).");

			var list = LoadPseudocodePreferIndex(analysisDir);
			var match = input["match"]?.Value<string>() ?? "contains";
			var caseSensitive = input["caseSensitive"]?.Value<bool?>() ?? false;
			var limit = Math.Clamp(input["limit"]?.Value<int?>() ?? 10, 1, 200);
			var snippetChars = Math.Clamp(input["snippetChars"]?.Value<int?>() ?? 300, 50, 2000);

			var queryNorm = caseSensitive ? query : query!.ToLowerInvariant();
			var results = new List<JObject>();
			var total = 0;

			foreach (var entry in list) {
				var code = entry.Pseudocode ?? string.Empty;
				var codeNorm = caseSensitive ? code : (entry.PseudocodeLower ?? code.ToLowerInvariant());
				var index = IndexOfMatch(codeNorm, queryNorm, match);
				if (index < 0)
					continue;

				total++;
				if (results.Count >= limit)
					continue;

				results.Add(new JObject {
					["name"] = entry.Name,
					["ea"] = entry.Ea,
					["signature"] = entry.Signature,
					["fallback"] = entry.Fallback,
					["snippet"] = BuildSnippet(code, index, snippetChars),
				});
			}

			var payload = new JObject {
				["count"] = results.Count,
				["total"] = total,
				["matches"] = new JArray(results),
			};
			return ToolOk(id, payload);
		}

		JObject HandleAnalysisPseudocodeGet(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");

			var name = input["name"]?.Value<string>();
			var ea = input["ea"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(ea))
				return ToolError(id, "Missing name or ea");

			var analysisDir = ResolveAnalysisDir(jobId, input);
			if (string.IsNullOrWhiteSpace(analysisDir))
				return ToolError(id, "Missing analysis directory (set idaOutputDir or run ida_analyze first).");

			var list = LoadPseudocodePreferIndex(analysisDir);
			var caseSensitive = input["caseSensitive"]?.Value<bool?>() ?? false;
			var nameNorm = caseSensitive ? name : name?.ToLowerInvariant();
			var maxChars = Math.Clamp(input["maxChars"]?.Value<int?>() ?? 4000, 500, 20000);

			foreach (var entry in list) {
				if (!string.IsNullOrWhiteSpace(name)) {
					var entryName = entry.Name ?? string.Empty;
					var entryNorm = caseSensitive ? entryName : (entry.NameLower ?? entryName.ToLowerInvariant());
					if (entryNorm != nameNorm)
						continue;
				}
				else if (!string.IsNullOrWhiteSpace(ea)) {
					if (!string.Equals(entry.Ea, ea, StringComparison.OrdinalIgnoreCase))
						continue;
				}

				var code = entry.Pseudocode ?? string.Empty;
				var truncated = code.Length > maxChars;
				var text = truncated ? code.Substring(0, maxChars) : code;
				var payload = new JObject {
					["name"] = entry.Name,
					["ea"] = entry.Ea,
					["endEa"] = entry.EndEa,
					["size"] = entry.Size,
					["signature"] = entry.Signature,
					["pseudocode"] = text,
					["fallback"] = entry.Fallback,
					["truncated"] = truncated || entry.Truncated,
				};
				return ToolOk(id, payload);
			}

			return ToolError(id, "Pseudocode not found.");
		}

		JObject HandlePatchCodegen(JToken? id, JObject input) {
			var requirements = input["requirements"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(requirements))
				return ToolError(id, "Missing requirements");

			var artifactsToken = input["analysisArtifacts"] as JArray;
			var artifacts = new List<string>();
			if (artifactsToken is not null) {
				foreach (var token in artifactsToken) {
					var value = token?.Value<string>();
					if (!string.IsNullOrWhiteSpace(value))
						artifacts.Add(value);
				}
			}

			var outputDir = Path.Combine(config.WorkspaceRoot, "patches", DateTime.UtcNow.ToString("yyyyMMdd_HHmmss"));
			PatchCodegenResult result;
			try {
				result = PatchCodegenRunner.Run(requirements, artifacts, outputDir);
			}
			catch (Exception ex) {
				return ToolError(id, $"patch_codegen failed: {ex.Message}");
			}

			var payload = new JObject {
				["outputDir"] = result.OutputDir,
				["files"] = new JArray(result.Files),
			};
			return ToolOk(id, payload);
		}

		JObject HandlePackageMod(JToken? id, JObject input) {
			var outputDir = input["outputDir"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(outputDir))
				return ToolError(id, "Missing outputDir");

			PackageModResult result;
			try {
				result = PackageModRunner.Run(outputDir);
			}
			catch (Exception ex) {
				return ToolError(id, $"package_mod failed: {ex.Message}");
			}

			var payload = new JObject {
				["outputDir"] = result.OutputDir,
				["manifestPath"] = result.ManifestPath,
				["installPath"] = result.InstallPath,
				["rollbackPath"] = result.RollbackPath,
				["packagePath"] = result.PackagePath,
				["payloadFiles"] = new JArray(result.PayloadFiles),
			};
			return ToolOk(id, payload);
		}

		static bool PathsEqual(string left, string right) {
			try {
				var leftFull = Path.GetFullPath(left)
					.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
				var rightFull = Path.GetFullPath(right)
					.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
				return string.Equals(leftFull, rightFull, StringComparison.OrdinalIgnoreCase);
			}
			catch {
				return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
			}
		}

		static IdaAnalyzeResult RunIdaExport(string? idaPath, string databasePath, string scriptPath, string outputPath, string? nameFilter) {
			if (string.IsNullOrWhiteSpace(idaPath))
				return new IdaAnalyzeResult(false, -1, databasePath, databasePath, string.Empty, string.Empty, "Missing idaPath.");
			if (!File.Exists(idaPath))
				return new IdaAnalyzeResult(false, -1, databasePath, databasePath, string.Empty, string.Empty, $"idaPath not found: {idaPath}");

			var args = new List<string> {
				outputPath,
			};
			if (!string.IsNullOrWhiteSpace(nameFilter))
				args.Add(nameFilter);

			try {
				return IdaHeadlessRunner.RunAsync(
					idaPath,
					databasePath,
					Path.GetDirectoryName(databasePath) ?? string.Empty,
					scriptPath,
					args,
					CancellationToken.None).GetAwaiter().GetResult();
			}
			catch (Exception ex) {
				return new IdaAnalyzeResult(false, -1, databasePath, databasePath, string.Empty, string.Empty, ex.Message);
			}
		}

		static string? FindIdaDatabase(string analysisDir) {
			if (!Directory.Exists(analysisDir))
				return null;

			var i64 = Directory.EnumerateFiles(analysisDir, "*.i64", SearchOption.TopDirectoryOnly).FirstOrDefault();
			if (!string.IsNullOrWhiteSpace(i64))
				return i64;
			return Directory.EnumerateFiles(analysisDir, "*.idb", SearchOption.TopDirectoryOnly).FirstOrDefault();
		}

		string? ResolveAnalysisDir(string jobId, JObject input) {
			if (!string.IsNullOrWhiteSpace(jobId)) {
				var idbDir = input["idbDir"]?.Value<string>();
				if (!string.IsNullOrWhiteSpace(idbDir))
					return idbDir;

				var fromJob = ReadJobParam(jobId, "idbDir");
				if (!string.IsNullOrWhiteSpace(fromJob))
					return fromJob;
			}

			return string.IsNullOrWhiteSpace(config.IdaOutputDir) ? null : config.IdaOutputDir;
		}

		string? ReadJobParam(string jobId, string key) {
			try {
				var jobPath = Path.Combine(config.WorkspaceRoot, jobId, "job.json");
				if (!File.Exists(jobPath))
					return null;

				var jobJson = JObject.Parse(File.ReadAllText(jobPath));
				var paramsToken = jobJson["ParamsJson"] ?? jobJson["paramsJson"];
				var paramsText = paramsToken?.Value<string>();
				if (string.IsNullOrWhiteSpace(paramsText))
					return null;

				var paramsObj = JObject.Parse(paramsText);
				return paramsObj[key]?.Value<string>();
			}
			catch {
				return null;
			}
		}

		List<SymbolEntry> LoadSymbolsPreferIndex(string analysisDir) {
			var symbolsPath = Path.Combine(analysisDir, "symbols.json");
			if (!File.Exists(symbolsPath))
				return new List<SymbolEntry>();

			var cachePath = GetIndexCachePath(symbolsPath, "symbols.index.json");
			if (File.Exists(cachePath))
				return LoadSymbols(cachePath);

			var localIndex = Path.Combine(analysisDir, "symbols.index.json");
			if (File.Exists(localIndex))
				return LoadSymbols(localIndex);

			return LoadSymbols(symbolsPath);
		}

		List<PseudocodeEntry> LoadPseudocodePreferIndex(string analysisDir) {
			var pseudocodePath = Path.Combine(analysisDir, "pseudocode.json");
			if (!File.Exists(pseudocodePath))
				return new List<PseudocodeEntry>();

			var cachePath = GetIndexCachePath(pseudocodePath, "pseudocode.index.json");
			if (File.Exists(cachePath))
				return LoadPseudocode(cachePath);

			var localIndex = Path.Combine(analysisDir, "pseudocode.index.json");
			if (File.Exists(localIndex))
				return LoadPseudocode(localIndex);

			return LoadPseudocode(pseudocodePath);
		}

		List<StringEntry> LoadStringsPreferIndex(string analysisDir) {
			var stringsPath = Path.Combine(analysisDir, "strings.json");
			if (!File.Exists(stringsPath))
				return new List<StringEntry>();

			var cachePath = GetIndexCachePath(stringsPath, "strings.index.json");
			if (File.Exists(cachePath))
				return LoadStrings(cachePath);

			var localIndex = Path.Combine(analysisDir, "strings.index.json");
			if (File.Exists(localIndex))
				return LoadStrings(localIndex);

			return LoadStrings(stringsPath);
		}

		static List<SymbolEntry> LoadSymbols(string path) {
			if (!File.Exists(path))
				return new List<SymbolEntry>();

			var root = JObject.Parse(File.ReadAllText(path));
			var items = root["symbols"] as JArray;
			if (items is null)
				return new List<SymbolEntry>();

			var list = new List<SymbolEntry>(items.Count);
			foreach (var token in items) {
				var obj = token as JObject;
				if (obj is null)
					continue;
				var callsToken = obj["calls"] as JArray;
				var callersToken = obj["callers"] as JArray;
				list.Add(new SymbolEntry {
					Name = obj["name"]?.Value<string>() ?? string.Empty,
					NameLower = obj["nameLower"]?.Value<string>(),
					Ea = obj["ea"]?.Value<string>() ?? string.Empty,
					EndEa = obj["endEa"]?.Value<string>(),
					Size = obj["size"]?.Value<long?>() ?? 0,
					Signature = obj["signature"]?.Value<string>(),
					SignatureLower = obj["signatureLower"]?.Value<string>(),
					Segment = obj["segment"]?.Value<string>(),
					Calls = callsToken is null ? null : callsToken.Values<string>().Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!).ToList(),
					Callers = callersToken is null ? null : callersToken.Values<string>().Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!).ToList(),
				});
			}
			return list;
		}

		static List<PseudocodeEntry> LoadPseudocode(string path) {
			if (!File.Exists(path))
				return new List<PseudocodeEntry>();

			var root = JObject.Parse(File.ReadAllText(path));
			var items = root["functions"] as JArray;
			if (items is null)
				return new List<PseudocodeEntry>();

			var list = new List<PseudocodeEntry>(items.Count);
			foreach (var token in items) {
				var obj = token as JObject;
				if (obj is null)
					continue;
				list.Add(new PseudocodeEntry {
					Name = obj["name"]?.Value<string>() ?? string.Empty,
					NameLower = obj["nameLower"]?.Value<string>(),
					Ea = obj["ea"]?.Value<string>() ?? string.Empty,
					EndEa = obj["endEa"]?.Value<string>(),
					Size = obj["size"]?.Value<long?>() ?? 0,
					Signature = obj["signature"]?.Value<string>(),
					Pseudocode = obj["pseudocode"]?.Value<string>() ?? string.Empty,
					PseudocodeLower = obj["pseudocodeLower"]?.Value<string>(),
					Fallback = obj["fallback"]?.Value<string>(),
					Truncated = obj["truncated"]?.Value<bool?>() ?? false,
				});
			}
			return list;
		}

		static List<StringEntry> LoadStrings(string path) {
			if (!File.Exists(path))
				return new List<StringEntry>();

			var root = JObject.Parse(File.ReadAllText(path));
			var items = root["strings"] as JArray;
			if (items is null)
				return new List<StringEntry>();

			var list = new List<StringEntry>(items.Count);
			foreach (var token in items) {
				var obj = token as JObject;
				if (obj is null)
					continue;
				List<StringRef>? refs = null;
				if (obj["refs"] is JArray refsToken) {
					refs = new List<StringRef>();
					foreach (var refToken in refsToken) {
						var refObj = refToken as JObject;
						if (refObj is null)
							continue;
						refs.Add(new StringRef {
							FuncEa = refObj["funcEa"]?.Value<string>() ?? string.Empty,
							FuncName = refObj["funcName"]?.Value<string>(),
							RefEa = refObj["refEa"]?.Value<string>() ?? string.Empty,
						});
					}
				}
				list.Add(new StringEntry {
					Ea = obj["ea"]?.Value<string>() ?? string.Empty,
					Value = obj["value"]?.Value<string>() ?? string.Empty,
					ValueLower = obj["valueLower"]?.Value<string>(),
					Length = obj["length"]?.Value<int?>() ?? 0,
					RefCount = obj["refCount"]?.Value<int?>() ?? 0,
					Refs = refs,
				});
			}
			return list;
		}

		static void SaveSymbolsIndex(string path, List<SymbolEntry> symbols) {
			Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
			var items = new JArray();
			foreach (var entry in symbols) {
				items.Add(new JObject {
					["name"] = entry.Name,
					["nameLower"] = entry.Name?.ToLowerInvariant(),
					["ea"] = entry.Ea,
					["endEa"] = entry.EndEa,
					["size"] = entry.Size,
					["signature"] = entry.Signature,
					["signatureLower"] = entry.Signature?.ToLowerInvariant(),
					["segment"] = entry.Segment,
					["calls"] = entry.Calls is null ? null : new JArray(entry.Calls),
					["callers"] = entry.Callers is null ? null : new JArray(entry.Callers),
				});
			}

			var root = new JObject {
				["count"] = symbols.Count,
				["symbols"] = items,
			};
			File.WriteAllText(path, root.ToString(Formatting.Indented));
		}

		static void SavePseudocodeIndex(string path, List<PseudocodeEntry> functions) {
			Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
			var items = new JArray();
			foreach (var entry in functions) {
				var code = entry.Pseudocode ?? string.Empty;
				items.Add(new JObject {
					["name"] = entry.Name,
					["nameLower"] = entry.Name?.ToLowerInvariant(),
					["ea"] = entry.Ea,
					["endEa"] = entry.EndEa,
					["size"] = entry.Size,
					["signature"] = entry.Signature,
					["pseudocode"] = code,
					["pseudocodeLower"] = code.ToLowerInvariant(),
					["fallback"] = entry.Fallback,
					["truncated"] = entry.Truncated,
				});
			}

			var root = new JObject {
				["count"] = functions.Count,
				["functions"] = items,
			};
			File.WriteAllText(path, root.ToString(Formatting.Indented));
		}

		static void SaveStringsIndex(string path, List<StringEntry> strings) {
			Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
			var items = new JArray();
			foreach (var entry in strings) {
				items.Add(new JObject {
					["ea"] = entry.Ea,
					["value"] = entry.Value,
					["valueLower"] = entry.Value?.ToLowerInvariant(),
					["length"] = entry.Length,
					["refCount"] = entry.RefCount,
					["refs"] = entry.Refs is null ? null : new JArray(entry.Refs.Select(r => new JObject {
						["funcEa"] = r.FuncEa,
						["funcName"] = r.FuncName,
						["refEa"] = r.RefEa,
					})),
				});
			}

			var root = new JObject {
				["count"] = strings.Count,
				["strings"] = items,
			};
			File.WriteAllText(path, root.ToString(Formatting.Indented));
		}

		Dictionary<string, SymbolEntry> BuildSymbolMap(List<SymbolEntry> list) {
			var map = new Dictionary<string, SymbolEntry>(StringComparer.OrdinalIgnoreCase);
			foreach (var entry in list) {
				var key = NormalizeEa(entry.Ea);
				if (!string.IsNullOrWhiteSpace(key) && !map.ContainsKey(key))
					map[key] = entry;
			}
			return map;
		}

		SymbolEntry? FindSymbol(List<SymbolEntry> list, string? name, string? ea, bool caseSensitive) {
			if (!string.IsNullOrWhiteSpace(name)) {
				var nameNorm = caseSensitive ? name : name!.ToLowerInvariant();
				foreach (var entry in list) {
					var entryName = entry.Name ?? string.Empty;
					var entryNorm = caseSensitive ? entryName : (entry.NameLower ?? entryName.ToLowerInvariant());
					if (entryNorm == nameNorm)
						return entry;
				}
				return null;
			}

			if (!string.IsNullOrWhiteSpace(ea)) {
				var target = NormalizeEa(ea);
				foreach (var entry in list) {
					var entryEa = NormalizeEa(entry.Ea);
					if (entryEa == target)
						return entry;
				}
			}

			return null;
		}

		static bool SymbolMatches(SymbolEntry entry, string field, string match, bool caseSensitive, string queryNorm, string queryEa) {
			if (field.Equals("ea", StringComparison.OrdinalIgnoreCase)) {
				var entryEa = NormalizeEa(entry.Ea);
				var query = NormalizeEa(queryEa);
				if (string.IsNullOrWhiteSpace(query))
					return false;
				return IsMatch(entryEa, query, match);
			}

			if (field.Equals("signature", StringComparison.OrdinalIgnoreCase)) {
				var sig = entry.Signature ?? string.Empty;
				var sigNorm = caseSensitive ? sig : (entry.SignatureLower ?? sig.ToLowerInvariant());
				return IsMatch(sigNorm, queryNorm, match);
			}

			var name = entry.Name ?? string.Empty;
			var nameNorm = caseSensitive ? name : (entry.NameLower ?? name.ToLowerInvariant());
			return IsMatch(nameNorm, queryNorm, match);
		}

		static string NormalizeEa(string? value) {
			if (string.IsNullOrWhiteSpace(value))
				return string.Empty;
			var text = value.Trim();
			if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
				text = text[2..];
			if (ulong.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
				return $"0x{hex:x}";
			if (ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec))
				return $"0x{dec:x}";
			return value.Trim().ToLowerInvariant();
		}

		string GetIndexCachePath(string artifactPath, string indexFileName) {
			var info = new FileInfo(artifactPath);
			var key = ComputeHash($"{artifactPath}|{info.Length}|{info.LastWriteTimeUtc.Ticks}");
			var cacheDir = Path.Combine(config.WorkspaceRoot, "index-cache");
			Directory.CreateDirectory(cacheDir);
			return Path.Combine(cacheDir, $"{key}.{indexFileName}");
		}

		static string ComputeHash(string input) {
			using var sha = SHA256.Create();
			var bytes = Encoding.UTF8.GetBytes(input);
			var hash = sha.ComputeHash(bytes);
			return Convert.ToHexString(hash).ToLowerInvariant();
		}

		static JObject SelectSymbolFields(SymbolEntry entry, JArray? fields) {
			if (fields is null || fields.Count == 0) {
				return new JObject {
					["name"] = entry.Name,
					["ea"] = entry.Ea,
					["endEa"] = entry.EndEa,
					["size"] = entry.Size,
					["signature"] = entry.Signature,
					["segment"] = entry.Segment,
					["calls"] = entry.Calls is null ? null : new JArray(entry.Calls),
					["callers"] = entry.Callers is null ? null : new JArray(entry.Callers),
				};
			}

			var obj = new JObject();
			foreach (var field in fields) {
				var name = field?.Value<string>();
				switch (name) {
					case "name":
						obj["name"] = entry.Name;
						break;
					case "ea":
						obj["ea"] = entry.Ea;
						break;
					case "endEa":
						obj["endEa"] = entry.EndEa;
						break;
					case "size":
						obj["size"] = entry.Size;
						break;
					case "signature":
						obj["signature"] = entry.Signature;
						break;
					case "segment":
						obj["segment"] = entry.Segment;
						break;
					case "calls":
						obj["calls"] = entry.Calls is null ? null : new JArray(entry.Calls);
						break;
					case "callers":
						obj["callers"] = entry.Callers is null ? null : new JArray(entry.Callers);
						break;
				}
			}
			return obj;
		}

		static bool IsMatch(string value, string query, string mode) {
			if (string.Equals(mode, "exact", StringComparison.OrdinalIgnoreCase))
				return string.Equals(value, query, StringComparison.Ordinal);
			return value.Contains(query, StringComparison.Ordinal);
		}

		static int IndexOfMatch(string value, string query, string mode) {
			if (string.Equals(mode, "exact", StringComparison.OrdinalIgnoreCase))
				return string.Equals(value, query, StringComparison.Ordinal) ? 0 : -1;
			return value.IndexOf(query, StringComparison.Ordinal);
		}

		static string BuildSnippet(string text, int index, int snippetChars) {
			if (string.IsNullOrEmpty(text))
				return string.Empty;
			if (index < 0)
				index = 0;
			var start = Math.Max(0, index - snippetChars / 2);
			var length = Math.Min(snippetChars, text.Length - start);
			return text.Substring(start, length);
		}

		static bool MetaMatchesExpectedDb(string databasePath, UnityLocateResult locate, string scriptJsonPath, string il2cppHeaderPath) {
			if (string.IsNullOrWhiteSpace(locate.GameAssemblyPath))
				return false;

			var metaPath = GetDbMetaPath(databasePath);
			if (!File.Exists(metaPath))
				return false;

			try {
				var metaJson = JObject.Parse(File.ReadAllText(metaPath));
				var metaGameDir = metaJson["gameDir"]?.Value<string>();
				var metaGameAssembly = metaJson["gameAssemblyPath"]?.Value<string>();
				var metaSize = metaJson["gameAssemblySize"]?.Value<long?>() ?? -1;
				var metaTicks = metaJson["gameAssemblyLastWriteUtcTicks"]?.Value<long?>() ?? -1;

				var currentAssembly = Path.GetFullPath(locate.GameAssemblyPath);
				var currentDir = Path.GetFullPath(locate.GameDir);
				var info = new FileInfo(currentAssembly);
				var scriptInfo = new FileInfo(scriptJsonPath);
				var headerInfo = new FileInfo(il2cppHeaderPath);

				if (!scriptInfo.Exists || !headerInfo.Exists)
					return false;

				if (!string.IsNullOrWhiteSpace(metaGameAssembly)) {
					var metaAssembly = Path.GetFullPath(metaGameAssembly);
					if (!string.Equals(metaAssembly, currentAssembly, StringComparison.OrdinalIgnoreCase))
						return false;
				}

				if (!string.IsNullOrWhiteSpace(metaGameDir)) {
					var metaDir = Path.GetFullPath(metaGameDir);
					if (!string.Equals(metaDir, currentDir, StringComparison.OrdinalIgnoreCase))
						return false;
				}

				if (metaSize >= 0 && metaSize != info.Length)
					return false;
				if (metaTicks >= 0 && metaTicks != info.LastWriteTimeUtc.Ticks)
					return false;

				var metaScriptSize = metaJson["scriptJsonSize"]?.Value<long?>() ?? -1;
				var metaScriptTicks = metaJson["scriptJsonLastWriteUtcTicks"]?.Value<long?>() ?? -1;
				var metaHeaderSize = metaJson["il2cppHeaderSize"]?.Value<long?>() ?? -1;
				var metaHeaderTicks = metaJson["il2cppHeaderLastWriteUtcTicks"]?.Value<long?>() ?? -1;

				if (metaScriptSize >= 0 && metaScriptSize != scriptInfo.Length)
					return false;
				if (metaScriptTicks >= 0 && metaScriptTicks != scriptInfo.LastWriteTimeUtc.Ticks)
					return false;
				if (metaHeaderSize >= 0 && metaHeaderSize != headerInfo.Length)
					return false;
				if (metaHeaderTicks >= 0 && metaHeaderTicks != headerInfo.LastWriteTimeUtc.Ticks)
					return false;

				return true;
			}
			catch {
				return false;
			}
		}

		static void TryWriteDbMeta(string databasePath, UnityLocateResult locate, string scriptJsonPath, string il2cppHeaderPath) {
			if (string.IsNullOrWhiteSpace(locate.GameAssemblyPath))
				return;

			try {
				var assemblyPath = Path.GetFullPath(locate.GameAssemblyPath);
				var info = new FileInfo(assemblyPath);
				if (!info.Exists)
					return;

				var scriptInfo = new FileInfo(scriptJsonPath);
				var headerInfo = new FileInfo(il2cppHeaderPath);
				if (!scriptInfo.Exists || !headerInfo.Exists)
					return;

				var meta = new JObject {
					["gameDir"] = Path.GetFullPath(locate.GameDir),
					["gameAssemblyPath"] = assemblyPath,
					["gameAssemblySize"] = info.Length,
					["gameAssemblyLastWriteUtcTicks"] = info.LastWriteTimeUtc.Ticks,
					["scriptJsonPath"] = Path.GetFullPath(scriptJsonPath),
					["scriptJsonSize"] = scriptInfo.Length,
					["scriptJsonLastWriteUtcTicks"] = scriptInfo.LastWriteTimeUtc.Ticks,
					["il2cppHeaderPath"] = Path.GetFullPath(il2cppHeaderPath),
					["il2cppHeaderSize"] = headerInfo.Length,
					["il2cppHeaderLastWriteUtcTicks"] = headerInfo.LastWriteTimeUtc.Ticks,
				};
				File.WriteAllText(GetDbMetaPath(databasePath), meta.ToString(Formatting.Indented));
			}
			catch {
			}
		}

		static string GetDbMetaPath(string databasePath) => databasePath + ".kiln.json";

		sealed class SymbolEntry {
			public string Name { get; set; } = string.Empty;
			public string? NameLower { get; set; }
			public string Ea { get; set; } = string.Empty;
			public string? EndEa { get; set; }
			public long Size { get; set; }
			public string? Signature { get; set; }
			public string? SignatureLower { get; set; }
			public string? Segment { get; set; }
			public List<string>? Calls { get; set; }
			public List<string>? Callers { get; set; }
		}

		sealed class PseudocodeEntry {
			public string Name { get; set; } = string.Empty;
			public string? NameLower { get; set; }
			public string Ea { get; set; } = string.Empty;
			public string? EndEa { get; set; }
			public long Size { get; set; }
			public string? Signature { get; set; }
			public string? Pseudocode { get; set; }
			public string? PseudocodeLower { get; set; }
			public string? Fallback { get; set; }
			public bool Truncated { get; set; }
		}

		sealed class StringEntry {
			public string Ea { get; set; } = string.Empty;
			public string? Value { get; set; }
			public string? ValueLower { get; set; }
			public int Length { get; set; }
			public int RefCount { get; set; }
			public List<StringRef>? Refs { get; set; }
		}

		sealed class StringRef {
			public string FuncEa { get; set; } = string.Empty;
			public string? FuncName { get; set; }
			public string RefEa { get; set; } = string.Empty;
		}

		static JObject ToolOk(JToken? id, JToken payload) {
			return ToolOk(id, payload.ToString(Formatting.Indented));
		}

		static JObject ToolOk(JToken? id, string text) {
			var content = new JArray {
				new JObject {
					["type"] = "text",
					["text"] = text,
				},
			};
			return MakeResult(id, new JObject {
				["content"] = content,
				["isError"] = false,
			});
		}

		static JObject ToolError(JToken? id, string message) {
			var content = new JArray {
				new JObject {
					["type"] = "text",
					["text"] = message,
				},
			};
			return MakeResult(id, new JObject {
				["content"] = content,
				["isError"] = true,
			});
		}

		static Task WriteResponseAsync(JObject response) =>
			Console.Out.WriteLineAsync(response.ToString(Formatting.None));

		static JObject MakeResult(JToken? id, JToken result) {
			return new JObject {
				["jsonrpc"] = "2.0",
				["id"] = id,
				["result"] = result,
			};
		}

		static JObject MakeError(JToken? id, int code, string message) {
			return new JObject {
				["jsonrpc"] = "2.0",
				["id"] = id,
				["error"] = new JObject {
					["code"] = code,
					["message"] = message,
				},
			};
		}

		const string HelpText =
@"Kiln MCP tools (quick guide)

Read first:
- kiln.exampleFlow (full usage examples)

Common flow:
1) workflow.run -> get job_id
2) workflow.status -> progress + stage
3) workflow.logs -> tail logs
4) workflow.cancel -> stop job

Notes:
- Use resources/list and resources/read to load embedded docs (e.g. BepInEx).";

		const string ExampleFlowText =
@"Kiln MCP example flow (detailed)

0) Read the docs tools
- kiln.exampleFlow: full usage examples (this text).
- kiln.help: short summary and tips.

1) Run a workflow (high-level, optional)
Tool: workflow.run
Purpose: Run a predefined workflow (currently Unity IL2CPP pipeline).
Arguments:
{
  ""flowName"": ""unity.il2cpp"",
  ""params"": {
    ""gameDir"": ""C:\\Games\\Example"",
    ""outputDir"": ""C:\\Kiln\\output""
  }
}
Notes:
- outputDir is workflow-specific; step tools below are more flexible.
Returns: { ""jobId"": ""..."" }

2) Check status
Tool: workflow.status
Purpose: Read job progress/stage/state.
Arguments: { ""jobId"": ""..."" }
Returns: { ""percent"": 0-100, ""stage"": ""..."", ""state"": ""Running|Completed|Failed"" }

3) Tail logs
Tool: workflow.logs
Purpose: Stream recent job log lines (headless tools print here).
Arguments: { ""jobId"": ""..."", ""tail"": 200 }

4) Cancel
Tool: workflow.cancel
Purpose: Stop a running job (best-effort).
Arguments: { ""jobId"": ""..."" }

5) Step tools (recommended for precise control)
- detect_engine
  Purpose: Identify Unity/Mono/IL2CPP fingerprints.
  Notes: Use before running IL2CPP tools.
  Args: { ""gameDir"": ""C:\\Games\\Example"" }
- unity_locate
  Purpose: Locate GameAssembly.dll / global-metadata.dat paths.
  Notes: Returns IL2CPP metadata + managed/data folders.
  Args: { ""gameDir"": ""C:\\Games\\Example"" }
- il2cpp_dump
  Purpose: Run Il2CppDumper to create script.json + il2cpp.h.
  Notes:
  - Output dir is enforced: il2cppRootDir/<game-name>.
  - dumperPath override must match config il2cppRootDir or its Il2CppDumper.exe.
  Args: { ""gameDir"": ""C:\\Games\\Example"" }
- ida_analyze
  Purpose: Run IDA headless analysis and auto-load Il2CppDumper symbols.
  Notes:
  - Uses idaPath from kiln.config.json (override blocked).
  - Reuses existing DB only if metadata matches current game + dump inputs.
  - idbDir defaults to idaOutputDir/<game-name>.
  Args: { ""gameDir"": ""C:\\Games\\Example"", ""idaPath"": ""C:\\Program Files\\IDA Professional 9.2\\idat64.exe"", ""reuseExisting"": true }
- ida_register_db
  Purpose: Import a pre-existing .i64/.idb into Kiln (no re-analysis).
  Notes:
  - Requires script.json + il2cpp.h in il2cppRootDir/<game-name>.
  - Writes .kiln.json metadata next to the DB.
  - copyToIdbDir=true copies DB into idaOutputDir/<game-name>.
  Args: { ""gameDir"": ""C:\\Games\\Example"", ""databasePath"": ""C:\\Tools\\GameAssembly.i64"", ""copyToIdbDir"": true, ""overwrite"": false }
- ida_export_symbols
  Purpose: Export functions, signatures, sizes, call graph, and strings.
  Notes: Produces symbols.json + strings.json in analysis directory.
  Args: { ""jobId"": ""..."" }
- ida_export_pseudocode
  Purpose: Export pseudocode for functions (Hex-Rays).
  Notes: Falls back to disassembly if Hex-Rays not available.
  Args: { ""jobId"": ""..."", ""nameFilter"": ""Player"" }

6) Offline analysis tools (AI-friendly search)
- analysis.index.build
  Purpose: Build local + cached indexes (symbols, strings, pseudocode).
  Notes: Speeds up subsequent searches across jobs.
  Args: { ""jobId"": ""..."" }
- analysis.symbols.search
  Purpose: Search symbols by name/signature/address.
  Notes: field=name|signature|ea, match=contains|exact.
  Args: { ""jobId"": ""..."", ""query"": ""Player"", ""field"": ""name"", ""match"": ""contains"", ""limit"": 20, ""fields"": [""name"", ""ea"", ""signature""] }
- analysis.symbols.get
  Purpose: Fetch full symbol entry by name or address.
  Args: { ""jobId"": ""..."", ""name"": ""Player_Update"" }
- analysis.symbols.xrefs
  Purpose: Get callers/callees (call graph) for a function.
  Args: { ""jobId"": ""..."", ""name"": ""Player_Update"", ""direction"": ""both"", ""limit"": 50 }
- analysis.strings.search
  Purpose: Search string literals and optionally return referencing functions.
  Notes: includeRefs=true returns func refs for fast triage.
  Args: { ""jobId"": ""..."", ""query"": ""weapon"", ""match"": ""contains"", ""includeRefs"": true, ""maxRefs"": 20 }
- analysis.pseudocode.search
  Purpose: Search pseudocode/disassembly text and return snippets.
  Args: { ""jobId"": ""..."", ""query"": ""weaponId"", ""limit"": 10, ""snippetChars"": 300 }
- analysis.pseudocode.get
  Purpose: Fetch full pseudocode/disassembly for a function.
  Args: { ""jobId"": ""..."", ""name"": ""Player_Update"", ""maxChars"": 4000 }

7) Patch generation + packaging
- patch_codegen
  Purpose: Generate patch template + target shortlist from analysis artifacts.
  Notes: Outputs patch_targets.json + PatchTargets.cs + Plugin.cs.
  Args: { ""requirements"": ""..."", ""analysisArtifacts"": [""...""] }
- package_mod
  Purpose: Package output directory into zip with manifest/install/rollback.
  Notes: Writes package zip into outputDir.
  Args: { ""outputDir"": ""C:\\Kiln\\output"" }

8) MCP resources (BepInEx docs)
- List resources: resources/list
- Read a resource: resources/read { ""uri"": ""bepinex://docs/il2cpp-guide"" }";
	}
}
