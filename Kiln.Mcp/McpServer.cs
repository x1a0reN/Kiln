using System;
using System.IO;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
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
		readonly IdaMcpProxy? idaProxy;
		bool hasReadExampleFlow;

		public McpServer(JobManager jobManager, KilnConfig config) {
			this.jobManager = jobManager ?? throw new ArgumentNullException(nameof(jobManager));
			this.config = config ?? throw new ArgumentNullException(nameof(config));
			catalog = new ToolCatalog();
			resources = new ResourceCatalog();
			idaProxy = IdaMcpProxy.TryCreate(config);
			hasReadExampleFlow = false;
		}

		public async Task RunAsync(CancellationToken token) {
			try {
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
			finally {
				idaProxy?.Dispose();
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
				return await ToolsListAsync(id, token).ConfigureAwait(false);
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

		async Task<JObject> ToolsListAsync(JToken? id, CancellationToken token) {
			var tools = new List<JObject>();
			foreach (var tool in catalog.Tools.Values) {
				tools.Add(new JObject {
					["name"] = tool.Name,
					["description"] = tool.Description,
					["inputSchema"] = tool.InputSchema,
				});
			}

			if (idaProxy is not null && idaProxy.Enabled) {
				var proxyTools = await idaProxy.GetToolsAsync(token).ConfigureAwait(false);
				foreach (var tool in proxyTools) {
					var description = string.IsNullOrWhiteSpace(tool.Description)
						? "ida-pro-mcp tool"
						: tool.Description + " (via ida-pro-mcp)";
					tools.Add(new JObject {
						["name"] = idaProxy.Prefix + tool.Name,
						["description"] = description,
						["inputSchema"] = tool.InputSchema,
					});
				}
			}

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

			KilnLog.Info($"tool call: {name}");
			if (name != "kiln.exampleFlow" && name != "kiln.help" && !hasReadExampleFlow) {
				return ToolError(id, "Please call kiln.exampleFlow first to read tool guidance before invoking other tools.");
			}

			if (!catalog.Tools.TryGetValue(name, out var tool)) {
				if (idaProxy is not null && idaProxy.Enabled && idaProxy.IsProxyTool(name)) {
					var proxyResult = await idaProxy.CallToolAsync(name, input, token).ConfigureAwait(false);
					return MakeResult(id, proxyResult);
				}

				if (idaProxy is null || !idaProxy.Enabled) {
					if (!string.IsNullOrWhiteSpace(name) && name.StartsWith("ida.", StringComparison.OrdinalIgnoreCase))
						return ToolError(id, "ida-pro-mcp proxy is disabled. Configure kiln.config.json (idaMcpEnabled + idaMcpCommand).");
				}

				return MakeError(id, -32601, $"Unknown tool: {name}");
			}

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
				hasReadExampleFlow = true;
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
			if (tool.Method == "analysis.pseudocode.ensure")
				return HandleAnalysisPseudocodeEnsure(id, input);
			if (tool.Method == "patch_codegen")
				return await HandlePatchCodegenAsync(id, input, token).ConfigureAwait(false);
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
					var env = new Dictionary<string, string> {
						["KILN_SYMBOL_SCRIPT"] = symbolScriptPath,
						["KILN_SCRIPT_JSON"] = scriptJson,
						["KILN_IL2CPP_HEADER"] = il2cppHeader,
					};
					result = await IdaHeadlessRunner.RunAsync(
						idaPath,
						locate.GameAssemblyPath,
						idbDir,
						autoLoadScript,
						null,
						context.Token,
						context.Log,
						env).ConfigureAwait(false);
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

			var runAsync = input["async"]?.Value<bool?>() ?? true;
			if (runAsync) {
				var exportJob = StartIdaExportJob(
					"ida.export.symbols",
					databasePath,
					scriptPath,
					exportPath,
					null,
					buildSymbolsIndex: true,
					buildPseudocodeIndex: false);
				if (exportJob is null)
					return ToolError(id, "Failed to start symbols export job.");
				var payloadAsync = new JObject {
					["jobId"] = exportJob.JobId,
					["outputPath"] = exportPath,
					["databasePath"] = databasePath,
					["async"] = true,
				};
				return ToolOk(id, payloadAsync);
			}

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

			var runAsync = input["async"]?.Value<bool?>() ?? true;
			if (runAsync) {
				var exportJob = StartIdaExportJob(
					"ida.export.pseudocode",
					databasePath,
					scriptPath,
					exportPath,
					nameFilter,
					buildSymbolsIndex: false,
					buildPseudocodeIndex: true);
				if (exportJob is null)
					return ToolError(id, "Failed to start pseudocode export job.");
				var payloadAsync = new JObject {
					["jobId"] = exportJob.JobId,
					["outputPath"] = exportPath,
					["databasePath"] = databasePath,
					["async"] = true,
				};
				return ToolOk(id, payloadAsync);
			}

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
			var autoExport = input["autoExport"]?.Value<bool?>() ?? true;
			var autoExportLimit = Math.Clamp(input["autoExportLimit"]?.Value<int?>() ?? 30, 1, 200);
			var exportAll = input["exportAll"]?.Value<bool?>() ?? false;

			var queryNorm = caseSensitive ? query : query!.ToLowerInvariant();
			var results = new List<JObject>();
			var total = 0;
			var autoExported = 0;
			var autoExportTargets = 0;
			string? autoExportError = null;
			string? autoExportJobId = null;
			string? exportAllJobId = null;

			SearchPseudocode(list, queryNorm, match, caseSensitive, limit, snippetChars, results, ref total);

			if (results.Count == 0 && autoExport) {
				var candidates = SelectPseudocodeCandidates(analysisDir, query, match, caseSensitive, autoExportLimit);
				autoExportTargets = candidates.Count;
				if (candidates.Count > 0) {
					var exportJob = StartPseudocodeExportTargetsJob(analysisDir, candidates, caseSensitive);
					if (exportJob is not null) {
						autoExported = 0;
						autoExportError = null;
						autoExportJobId = exportJob.JobId;
					}
					else {
						autoExportError = "Failed to start pseudocode export job.";
					}
				}
			}

			if (results.Count == 0 && exportAll && string.IsNullOrWhiteSpace(exportAllJobId)) {
				var exportJob = StartPseudocodeExportAllJob(analysisDir);
				if (exportJob is not null)
					exportAllJobId = exportJob.JobId;
			}

			var payload = new JObject {
				["count"] = results.Count,
				["total"] = total,
				["matches"] = new JArray(results),
				["autoExported"] = autoExported,
				["autoExportTargets"] = autoExportTargets,
			};
			if (!string.IsNullOrWhiteSpace(autoExportError))
				payload["autoExportError"] = autoExportError;
			if (!string.IsNullOrWhiteSpace(autoExportJobId)) {
				payload["autoExportStarted"] = true;
				payload["autoExportJobId"] = autoExportJobId;
			}
			if (!string.IsNullOrWhiteSpace(exportAllJobId)) {
				payload["exportAllStarted"] = true;
				payload["exportAllJobId"] = exportAllJobId;
			}
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
			var autoExport = input["autoExport"]?.Value<bool?>() ?? true;
			var maxChars = Math.Clamp(input["maxChars"]?.Value<int?>() ?? 4000, 500, 20000);

			var found = FindPseudocodeEntry(list, name, ea, caseSensitive);
			if (found is null && autoExport) {
				var target = ResolvePseudocodeTarget(analysisDir, name, ea, caseSensitive);
				if (target is not null) {
					var exportJob = StartPseudocodeExportTargetsJob(analysisDir, new List<PseudocodeTarget> { target }, caseSensitive);
					if (exportJob is null)
						return ToolError(id, "Failed to start pseudocode export job.");
					var pendingPayload = new JObject {
						["pending"] = true,
						["exportJobId"] = exportJob.JobId,
						["analysisDir"] = analysisDir,
					};
					return ToolOk(id, pendingPayload);
				}
			}

			if (found is null)
				return ToolError(id, "Pseudocode not found.");

			var code = found.Pseudocode ?? string.Empty;
			var truncated = code.Length > maxChars;
			var text = truncated ? code.Substring(0, maxChars) : code;
			var payload = new JObject {
				["name"] = found.Name,
				["ea"] = found.Ea,
				["endEa"] = found.EndEa,
				["size"] = found.Size,
				["signature"] = found.Signature,
				["pseudocode"] = text,
				["fallback"] = found.Fallback,
				["truncated"] = truncated || found.Truncated,
			};
			return ToolOk(id, payload);
		}

		JObject HandleAnalysisPseudocodeEnsure(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");

			var analysisDir = ResolveAnalysisDir(jobId, input);
			if (string.IsNullOrWhiteSpace(analysisDir))
				return ToolError(id, "Missing analysis directory (set idaOutputDir or run ida_analyze first).");

			var exportAll = input["exportAll"]?.Value<bool?>() ?? false;
			var caseSensitive = input["caseSensitive"]?.Value<bool?>() ?? false;
			var maxTargets = Math.Clamp(input["maxTargets"]?.Value<int?>() ?? 50, 1, 500);
			var runAsync = input["async"]?.Value<bool?>() ?? true;
			var names = ReadStringArray(input["names"]);
			var eas = ReadStringArray(input["eas"]);

			if (exportAll) {
				var exportJob = StartPseudocodeExportAllJob(analysisDir);
				if (exportJob is null)
					return ToolError(id, "Failed to start pseudocode export job.");
				var payloadAll = new JObject {
					["exportAll"] = true,
					["exportJobId"] = exportJob.JobId,
					["analysisDir"] = analysisDir,
				};
				return ToolOk(id, payloadAll);
			}

			if ((names.Count == 0) && (eas.Count == 0))
				return ToolError(id, "Missing names or eas");

			var targets = ResolvePseudocodeTargets(analysisDir, names, eas, caseSensitive, maxTargets);
			if (targets.Count == 0)
				return ToolError(id, "No resolvable pseudocode targets.");

			if (runAsync) {
				var exportJob = StartPseudocodeExportTargetsJob(analysisDir, targets, caseSensitive);
				if (exportJob is null)
					return ToolError(id, "Failed to start pseudocode export job.");
				var payloadAsync = new JObject {
					["requested"] = targets.Count,
					["exported"] = 0,
					["analysisDir"] = analysisDir,
					["exportJobId"] = exportJob.JobId,
					["async"] = true,
				};
				return ToolOk(id, payloadAsync);
			}

			var ensure = EnsurePseudocodeTargets(analysisDir, targets, caseSensitive, CancellationToken.None);
			if (!ensure.Success)
				return ToolError(id, $"Pseudocode export failed: {ensure.Error ?? "unknown error"}");

			var payload = new JObject {
				["requested"] = targets.Count,
				["exported"] = ensure.Exported,
				["analysisDir"] = analysisDir,
				["outputPath"] = ensure.OutputPath,
			};
			return ToolOk(id, payload);
		}

		async Task<JObject> HandlePatchCodegenAsync(JToken? id, JObject input, CancellationToken token) {
			var requirements = input["requirements"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(requirements))
				return ToolError(id, "Missing requirements");

			var jobId = input["jobId"]?.Value<string>();
			var gameDir = input["gameDir"]?.Value<string>();
			var emitPluginProject = input["emitPluginProject"]?.Value<bool?>() ?? true;
			var projectName = input["projectName"]?.Value<string>();
			var pluginGuid = input["pluginGuid"]?.Value<string>();
			var analysisMode = input["analysisMode"]?.Value<string>() ?? "auto";
			var analysisDir = input["analysisDir"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(analysisDir)) {
				if (!string.IsNullOrWhiteSpace(jobId))
					analysisDir = ResolveAnalysisDir(jobId, input);
				else if (!string.IsNullOrWhiteSpace(gameDir))
					analysisDir = config.GetIdaOutputDirForGame(gameDir);
				else if (!string.IsNullOrWhiteSpace(config.IdaOutputDir))
					analysisDir = config.IdaOutputDir;
			}

			var outputDir = Path.Combine(config.WorkspaceRoot, "patches", DateTime.UtcNow.ToString("yyyyMMdd_HHmmss"));
			List<string> resolvedArtifacts;
			var useLive = ShouldUseLiveAnalysis(analysisMode);
			if (!useLive && analysisMode.Equals("live", StringComparison.OrdinalIgnoreCase))
				return ToolError(id, "analysisMode=live requires ida-pro-mcp proxy to be enabled.");
			if (useLive) {
				try {
					resolvedArtifacts = await BuildLiveArtifactsAsync(requirements, input, outputDir, token).ConfigureAwait(false);
				}
				catch (Exception ex) {
					return ToolError(id, $"patch_codegen live analysis failed: {ex.Message}");
				}
			}
			else {
				var artifactsToken = input["analysisArtifacts"] as JArray;
				var artifacts = new List<string>();
				if (artifactsToken is not null) {
					foreach (var item in artifactsToken) {
						var value = item?.Value<string>();
						if (!string.IsNullOrWhiteSpace(value))
							artifacts.Add(value);
					}
				}

				resolvedArtifacts = ResolveAnalysisArtifacts(analysisDir, artifacts);
			}

			PatchCodegenResult result;
			try {
				result = PatchCodegenRunner.Run(requirements, resolvedArtifacts, outputDir);
			}
			catch (Exception ex) {
				return ToolError(id, $"patch_codegen failed: {ex.Message}");
			}

			PluginProjectResult? pluginProject = null;
			if (emitPluginProject) {
				var projectGameDir = gameDir;
				if (string.IsNullOrWhiteSpace(projectGameDir) && !string.IsNullOrWhiteSpace(jobId))
					projectGameDir = ReadJobParam(jobId, "gameDir");
				if (!string.IsNullOrWhiteSpace(projectGameDir)) {
					try {
						pluginProject = CreatePluginProject(projectGameDir, projectName, pluginGuid);
					}
					catch (Exception ex) {
						pluginProject = new PluginProjectResult {
							Success = false,
							Error = ex.Message,
						};
					}
				}
			}

			var payload = new JObject {
				["outputDir"] = result.OutputDir,
				["files"] = new JArray(result.Files),
				["analysisMode"] = useLive ? "live" : "offline",
			};
			if (useLive)
				payload["liveArtifacts"] = new JArray(resolvedArtifacts);
			if (pluginProject is not null) {
				payload["pluginProjectEmitted"] = pluginProject.Success;
				if (!string.IsNullOrWhiteSpace(pluginProject.ProjectDir))
					payload["pluginProjectDir"] = pluginProject.ProjectDir;
				if (pluginProject.Files.Count > 0)
					payload["pluginProjectFiles"] = new JArray(pluginProject.Files);
				if (!string.IsNullOrWhiteSpace(pluginProject.Runtime))
					payload["pluginProjectRuntime"] = pluginProject.Runtime;
				if (!string.IsNullOrWhiteSpace(pluginProject.Error))
					payload["pluginProjectError"] = pluginProject.Error;
			}
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

		bool ShouldUseLiveAnalysis(string mode) {
			if (mode.Equals("offline", StringComparison.OrdinalIgnoreCase))
				return false;
			if (idaProxy is null || !idaProxy.Enabled)
				return false;
			return true;
		}

		async Task<List<string>> BuildLiveArtifactsAsync(string requirements, JObject input, string outputDir, CancellationToken token) {
			if (idaProxy is null || !idaProxy.Enabled)
				throw new InvalidOperationException("ida-pro-mcp proxy is disabled.");

			Directory.CreateDirectory(outputDir);

			var databasePath = input["databasePath"]?.Value<string>();
			var autoStartIda = input["autoStartIda"]?.Value<bool?>();
			var allowAutoStart = autoStartIda ?? config.IdaMcpAutoStart;
			if (allowAutoStart)
				await idaProxy.TryAutoStartAsync(databasePath, token).ConfigureAwait(false);

			var keywords = ExtractKeywords(requirements);
			if (keywords.Count == 0) {
				foreach (var fallback in DefaultLiveKeywords)
					keywords.Add(fallback);
			}
			var maxFunctions = Math.Clamp(input["liveMaxFunctions"]?.Value<int?>() ?? 200, 10, 5000);
			var maxDecompile = Math.Clamp(input["liveMaxDecompile"]?.Value<int?>() ?? 40, 0, 200);
			var maxStringMatches = Math.Clamp(input["liveMaxStringMatches"]?.Value<int?>() ?? 100, 0, 10000);
			var maxStringXrefs = Math.Clamp(input["liveMaxStringXrefs"]?.Value<int?>() ?? 200, 0, 1000);

			var functions = new Dictionary<string, LiveFunctionInfo>(StringComparer.OrdinalIgnoreCase);
			var stringHits = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

			void AddFunction(string? ea, string? name, long size, int scoreBoost) {
				var normEa = NormalizeEa(ea);
				if (string.IsNullOrWhiteSpace(normEa))
					return;
				if (!functions.TryGetValue(normEa, out var info)) {
					info = new LiveFunctionInfo {
						Ea = normEa,
						Name = name ?? string.Empty,
						Size = size,
					};
					functions[normEa] = info;
				}
				else {
					if (string.IsNullOrWhiteSpace(info.Name) || info.Name.StartsWith("sub_", StringComparison.OrdinalIgnoreCase)) {
						if (!string.IsNullOrWhiteSpace(name))
							info.Name = name!;
					}
					if (size > info.Size)
						info.Size = size;
				}
				info.Score += scoreBoost;
			}

			void AddStringHit(string? funcEa, string? funcName, string keyword) {
				if (string.IsNullOrWhiteSpace(keyword))
					return;
				AddFunction(funcEa, funcName, 0, 1);
				var normEa = NormalizeEa(funcEa);
				if (string.IsNullOrWhiteSpace(normEa))
					return;
				if (!stringHits.TryGetValue(normEa, out var set)) {
					set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
					stringHits[normEa] = set;
				}
				set.Add(keyword);
			}

			if (keywords.Count > 0 && maxStringMatches > 0 && maxStringXrefs > 0) {
				foreach (var keyword in keywords) {
					var findArgs = new JObject {
						["pattern"] = Regex.Escape(keyword),
						["limit"] = maxStringMatches,
						["offset"] = 0,
					};
					JToken? findResult = null;
					try {
						findResult = await CallIdaToolStructuredAsync("ida.find_regex", findArgs, token, databasePath, allowAutoStart).ConfigureAwait(false);
					}
					catch {
						continue;
					}
					if (findResult is not JObject findObj)
						continue;

					var matches = new List<string>();
					if (findObj["matches"] is JArray found) {
						foreach (var entry in found.OfType<JObject>()) {
							var addr = entry["addr"]?.Value<string>();
							if (string.IsNullOrWhiteSpace(addr))
								continue;
							matches.Add(addr);
							if (matches.Count >= maxStringMatches)
								break;
						}
					}

					if (matches.Count == 0)
						continue;

					var xrefsArgs = new JObject {
						["addrs"] = new JArray(matches),
						["limit"] = maxStringXrefs,
					};
					JToken? xrefsResult = null;
					try {
						xrefsResult = await CallIdaToolStructuredAsync("ida.xrefs_to", xrefsArgs, token, databasePath, allowAutoStart).ConfigureAwait(false);
					}
					catch {
						continue;
					}
					if (xrefsResult is not JArray xrefsList)
						continue;

					foreach (var entry in xrefsList.OfType<JObject>()) {
						if (entry["xrefs"] is not JArray xrefs)
							continue;
						foreach (var xref in xrefs.OfType<JObject>()) {
							var fn = xref["fn"] as JObject;
							if (fn is null)
								continue;
							var addr = fn["addr"]?.Value<string>();
							var name = fn["name"]?.Value<string>();
							var size = ParseSize(fn["size"]?.Value<string>());
							AddFunction(addr, name, size, 1);
							AddStringHit(addr, name, keyword);
						}
					}
				}
			}

			if (functions.Count == 0) {
				var queryArray = new JArray();
				if (keywords.Count == 0) {
					queryArray.Add(new JObject {
						["offset"] = 0,
						["count"] = maxFunctions,
						["filter"] = "*",
					});
				}
				else {
					foreach (var keyword in keywords) {
						queryArray.Add(new JObject {
							["offset"] = 0,
							["count"] = maxFunctions,
							["filter"] = keyword,
						});
					}
				}

				try {
					var listArgs = new JObject {
						["queries"] = queryArray,
					};
					var listResult = await CallIdaToolStructuredAsync("ida.list_funcs", listArgs, token, databasePath, allowAutoStart).ConfigureAwait(false);
					if (listResult is JArray pages) {
						foreach (var page in pages.OfType<JObject>()) {
							if (page["data"] is not JArray data)
								continue;
							foreach (var entry in data.OfType<JObject>()) {
								var addr = entry["addr"]?.Value<string>();
								var name = entry["name"]?.Value<string>();
								var size = ParseSize(entry["size"]?.Value<string>());
								AddFunction(addr, name, size, 1);
							}
						}
					}
					else if (listResult is JObject pageObj && pageObj["data"] is JArray data) {
						foreach (var entry in data.OfType<JObject>()) {
							var addr = entry["addr"]?.Value<string>();
							var name = entry["name"]?.Value<string>();
							var size = ParseSize(entry["size"]?.Value<string>());
							AddFunction(addr, name, size, 1);
						}
					}
				}
				catch {
				}
			}

			var ordered = functions.Values
				.OrderByDescending(f => f.Score)
				.ThenByDescending(f => f.Size)
				.ThenBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
				.Take(maxFunctions)
				.ToList();

			var symbolsArray = new JArray();
			foreach (var func in ordered) {
				var name = string.IsNullOrWhiteSpace(func.Name) ? $"sub_{func.Ea.Trim().Replace("0x", string.Empty)}" : func.Name;
				symbolsArray.Add(new JObject {
					["name"] = name,
					["nameLower"] = name.ToLowerInvariant(),
					["ea"] = func.Ea,
					["endEa"] = null,
					["size"] = func.Size,
					["signature"] = null,
					["signatureLower"] = null,
					["calls"] = new JArray(),
					["callers"] = new JArray(),
				});
			}

			var stringEntries = new Dictionary<string, List<JObject>>(StringComparer.OrdinalIgnoreCase);
			foreach (var hit in stringHits) {
				var funcEa = hit.Key;
				functions.TryGetValue(funcEa, out var funcInfo);
				foreach (var value in hit.Value) {
					if (!stringEntries.TryGetValue(value, out var refs)) {
						refs = new List<JObject>();
						stringEntries[value] = refs;
					}
					refs.Add(new JObject {
						["funcEa"] = funcEa,
						["funcName"] = funcInfo?.Name,
						["refEa"] = null,
					});
				}
			}

			var stringsArray = new JArray();
			foreach (var entry in stringEntries.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase)) {
				var value = entry.Key;
				stringsArray.Add(new JObject {
					["ea"] = string.Empty,
					["value"] = value,
					["valueLower"] = value.ToLowerInvariant(),
					["length"] = value.Length,
					["refs"] = new JArray(entry.Value),
				});
			}

			var pseudocodeArray = new JArray();
			if (maxDecompile > 0) {
				foreach (var func in ordered.Take(maxDecompile)) {
					var decompileArgs = new JObject {
						["addr"] = func.Ea,
					};
					var decompileResult = await CallIdaToolStructuredAsync("ida.decompile", decompileArgs, token, databasePath, allowAutoStart).ConfigureAwait(false);
					var code = decompileResult?["code"]?.Value<string>();
					if (string.IsNullOrWhiteSpace(code))
						continue;
					var name = string.IsNullOrWhiteSpace(func.Name) ? $"sub_{func.Ea.Trim().Replace("0x", string.Empty)}" : func.Name;
					pseudocodeArray.Add(new JObject {
						["name"] = name,
						["ea"] = func.Ea,
						["pseudocode"] = code,
					});
				}
			}

			var symbolsPath = Path.Combine(outputDir, "live_symbols.json");
			var stringsPath = Path.Combine(outputDir, "live_strings.json");
			var pseudocodePath = Path.Combine(outputDir, "live_pseudocode.json");

			File.WriteAllText(symbolsPath, new JObject {
				["symbols"] = symbolsArray,
				["count"] = symbolsArray.Count,
			}.ToString(Formatting.Indented));

			File.WriteAllText(stringsPath, new JObject {
				["strings"] = stringsArray,
				["count"] = stringsArray.Count,
			}.ToString(Formatting.Indented));

			File.WriteAllText(pseudocodePath, new JObject {
				["functions"] = pseudocodeArray,
				["count"] = pseudocodeArray.Count,
			}.ToString(Formatting.Indented));

			return new List<string> { symbolsPath, stringsPath, pseudocodePath };
		}

		async Task<JToken?> CallIdaToolStructuredAsync(string toolName, JObject args, CancellationToken token, string? databasePath, bool allowAutoStart) {
			if (idaProxy is null || !idaProxy.Enabled)
				throw new InvalidOperationException("ida-pro-mcp proxy is disabled.");

			var result = await idaProxy.CallToolAsync(toolName, args, token).ConfigureAwait(false);
			if (result["isError"]?.Value<bool>() == true) {
				var errorText = result["content"]?.First?["text"]?.Value<string>() ?? "ida-pro-mcp call failed.";
				if (allowAutoStart && IsIdaConnectError(errorText)) {
					var started = await idaProxy.TryAutoStartAsync(databasePath, token).ConfigureAwait(false);
					if (started) {
						result = await idaProxy.CallToolAsync(toolName, args, token).ConfigureAwait(false);
						if (result["isError"]?.Value<bool>() == true) {
							errorText = result["content"]?.First?["text"]?.Value<string>() ?? errorText;
							throw new InvalidOperationException(errorText);
						}
					}
					else {
						throw new InvalidOperationException(errorText);
					}
				}
				else {
					throw new InvalidOperationException(errorText);
				}
			}

			var structured = result["structuredContent"];
			if (structured is JObject structuredObj) {
				if (structuredObj.TryGetValue("result", out var inner) && structuredObj.Count == 1)
					return inner;
				return structuredObj;
			}
			if (structured is not null)
				return structured;

			var text = result["content"]?.First?["text"]?.Value<string>();
			if (!string.IsNullOrWhiteSpace(text)) {
				try {
					return JToken.Parse(text);
				}
				catch {
				}
			}
			return null;
		}

		static bool IsIdaConnectError(string text) {
			if (string.IsNullOrWhiteSpace(text))
				return false;
			return text.Contains("Failed to connect to IDA Pro", StringComparison.OrdinalIgnoreCase)
				|| text.Contains("ConnectionRefused", StringComparison.OrdinalIgnoreCase)
				|| text.Contains("actively refused", StringComparison.OrdinalIgnoreCase)
				|| text.Contains("拒绝", StringComparison.OrdinalIgnoreCase);
		}

		static List<string> ExtractKeywords(string requirements) {
			var list = new List<string>();
			var buffer = new StringBuilder();
			foreach (var ch in requirements) {
				if (char.IsLetterOrDigit(ch) || ch == '_') {
					buffer.Append(ch);
					continue;
				}

				FlushToken(buffer, list);
			}
			FlushToken(buffer, list);
			var stopwords = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
				"mod", "mods", "hook", "hooks", "plugin", "plugins", "template", "templates",
				"patch", "patches", "kiln", "generate", "generated", "make", "create",
				"example", "samples", "demo", "test",
			};
			var allow = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "hp" };
			return list
				.Select(x => x.ToLowerInvariant())
				.Where(x => (x.Length >= 3 || allow.Contains(x)) && !stopwords.Contains(x))
				.Distinct(StringComparer.OrdinalIgnoreCase)
				.Take(24)
				.ToList();
		}

		static readonly string[] DefaultLiveKeywords = new[] {
			"spawn", "spawner", "enemy", "enemies", "wave", "summon", "create",
			"monster", "mob", "npc", "boss", "endless", "story",
		};

		static void FlushToken(StringBuilder buffer, List<string> list) {
			if (buffer.Length == 0)
				return;
			list.Add(buffer.ToString());
			buffer.Clear();
		}

		static long ParseSize(string? value) {
			if (string.IsNullOrWhiteSpace(value))
				return 0;
			var text = value.Trim();
			if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
				text = text[2..];
			if (long.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
				return hex;
			if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec))
				return dec;
			return 0;
		}

		static List<string> ReadStringArray(JToken? token) {
			var list = new List<string>();
			if (token is not JArray arr)
				return list;
			foreach (var item in arr) {
				var value = item?.Value<string>();
				if (!string.IsNullOrWhiteSpace(value))
					list.Add(value);
			}
			return list;
		}

		List<string> ResolveAnalysisArtifacts(string? analysisDir, List<string> artifacts) {
			var resolved = new List<string>();
			var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

			void AddIfExists(string path) {
				if (string.IsNullOrWhiteSpace(path))
					return;
				if (!File.Exists(path))
					return;
				var full = Path.GetFullPath(path);
				if (seen.Add(full))
					resolved.Add(full);
			}

			string? ResolveRelative(string item) {
				if (string.IsNullOrWhiteSpace(item) || string.IsNullOrWhiteSpace(analysisDir))
					return null;
				return Path.Combine(analysisDir, item);
			}

			foreach (var item in artifacts) {
				if (string.IsNullOrWhiteSpace(item))
					continue;
				if (Path.IsPathRooted(item)) {
					AddIfExists(item);
					continue;
				}

				var candidate = ResolveRelative(item);
				if (!string.IsNullOrWhiteSpace(candidate) && File.Exists(candidate)) {
					AddIfExists(candidate);
					continue;
				}

				if (!string.IsNullOrWhiteSpace(analysisDir)) {
					var fallback = ResolveArtifactFallback(analysisDir, item);
					AddIfExists(fallback);
				}
			}

			if (resolved.Count == 0 && !string.IsNullOrWhiteSpace(analysisDir)) {
				AddIfExists(Path.Combine(analysisDir, "symbols.index.json"));
				AddIfExists(Path.Combine(analysisDir, "symbols.json"));
				AddIfExists(Path.Combine(analysisDir, "strings.index.json"));
				AddIfExists(Path.Combine(analysisDir, "strings.json"));
				AddIfExists(Path.Combine(analysisDir, "pseudocode.index.json"));
				AddIfExists(Path.Combine(analysisDir, "pseudocode.json"));
			}

			return resolved;
		}

		string ResolveArtifactFallback(string analysisDir, string item) {
			var normalized = item.Replace('/', Path.DirectorySeparatorChar).Replace('\\', Path.DirectorySeparatorChar);
			if (normalized.EndsWith("symbols.index.json", StringComparison.OrdinalIgnoreCase))
				return Path.Combine(analysisDir, "symbols.json");
			if (normalized.EndsWith("symbols.json", StringComparison.OrdinalIgnoreCase))
				return Path.Combine(analysisDir, "symbols.index.json");
			if (normalized.EndsWith("strings.index.json", StringComparison.OrdinalIgnoreCase))
				return Path.Combine(analysisDir, "strings.json");
			if (normalized.EndsWith("strings.json", StringComparison.OrdinalIgnoreCase))
				return Path.Combine(analysisDir, "strings.index.json");
			if (normalized.EndsWith("pseudocode.index.json", StringComparison.OrdinalIgnoreCase))
				return Path.Combine(analysisDir, "pseudocode.json");
			if (normalized.EndsWith("pseudocode.json", StringComparison.OrdinalIgnoreCase))
				return Path.Combine(analysisDir, "pseudocode.index.json");
			return Path.Combine(analysisDir, item);
		}

		void SearchPseudocode(
			List<PseudocodeEntry> list,
			string queryNorm,
			string match,
			bool caseSensitive,
			int limit,
			int snippetChars,
			List<JObject> results,
			ref int total) {
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
		}

		PseudocodeEntry? FindPseudocodeEntry(List<PseudocodeEntry> list, string? name, string? ea, bool caseSensitive) {
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
					if (NormalizeEa(entry.Ea) == target)
						return entry;
				}
			}

			return null;
		}

		PseudocodeTarget? ResolvePseudocodeTarget(string analysisDir, string? name, string? ea, bool caseSensitive) {
			if (!string.IsNullOrWhiteSpace(ea))
				return new PseudocodeTarget { Ea = NormalizeEa(ea), Name = name };

			if (string.IsNullOrWhiteSpace(name))
				return null;

			var symbols = LoadSymbolsPreferIndex(analysisDir);
			var symbol = FindSymbol(symbols, name, null, caseSensitive);
			if (symbol is null)
				return new PseudocodeTarget { Name = name };

			return new PseudocodeTarget { Name = symbol.Name, Ea = symbol.Ea };
		}

		List<PseudocodeTarget> ResolvePseudocodeTargets(string analysisDir, List<string> names, List<string> eas, bool caseSensitive, int maxTargets) {
			var targets = new List<PseudocodeTarget>();
			var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			var symbols = names.Count == 0 ? new List<SymbolEntry>() : LoadSymbolsPreferIndex(analysisDir);

			foreach (var ea in eas) {
				if (targets.Count >= maxTargets)
					break;
				var norm = NormalizeEa(ea);
				if (string.IsNullOrWhiteSpace(norm))
					continue;
				var key = "ea:" + norm;
				if (seen.Add(key))
					targets.Add(new PseudocodeTarget { Ea = norm });
			}

			foreach (var name in names) {
				if (targets.Count >= maxTargets)
					break;
				if (string.IsNullOrWhiteSpace(name))
					continue;
				var symbol = FindSymbol(symbols, name, null, caseSensitive);
				var resolvedName = symbol?.Name ?? name;
				var resolvedEa = symbol?.Ea;
				var key = !string.IsNullOrWhiteSpace(resolvedEa)
					? "ea:" + NormalizeEa(resolvedEa)
					: "name:" + (caseSensitive ? resolvedName : resolvedName.ToLowerInvariant());
				if (seen.Add(key))
					targets.Add(new PseudocodeTarget { Name = resolvedName, Ea = resolvedEa });
			}

			return targets;
		}

		List<PseudocodeTarget> SelectPseudocodeCandidates(string analysisDir, string query, string match, bool caseSensitive, int limit) {
			var targets = new List<PseudocodeTarget>();
			var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			var queryNorm = caseSensitive ? query : query.ToLowerInvariant();

			void AddTarget(string? name, string? ea) {
				if (targets.Count >= limit)
					return;
				var key = !string.IsNullOrWhiteSpace(ea)
					? "ea:" + NormalizeEa(ea)
					: "name:" + (caseSensitive ? (name ?? string.Empty) : (name ?? string.Empty).ToLowerInvariant());
				if (string.IsNullOrWhiteSpace(key))
					return;
				if (!seen.Add(key))
					return;
				targets.Add(new PseudocodeTarget { Name = name, Ea = ea });
			}

			var symbols = LoadSymbolsPreferIndex(analysisDir);
			foreach (var entry in symbols) {
				if (targets.Count >= limit)
					break;
				var name = entry.Name ?? string.Empty;
				var sig = entry.Signature ?? string.Empty;
				var nameNorm = caseSensitive ? name : (entry.NameLower ?? name.ToLowerInvariant());
				var sigNorm = caseSensitive ? sig : (entry.SignatureLower ?? sig.ToLowerInvariant());
				if (IsMatch(nameNorm, queryNorm, match) || IsMatch(sigNorm, queryNorm, match))
					AddTarget(entry.Name, entry.Ea);
			}

			if (targets.Count >= limit)
				return targets;

			var strings = LoadStringsPreferIndex(analysisDir);
			foreach (var entry in strings) {
				if (targets.Count >= limit)
					break;
				var value = entry.Value ?? string.Empty;
				var valueNorm = caseSensitive ? value : (entry.ValueLower ?? value.ToLowerInvariant());
				if (!IsMatch(valueNorm, queryNorm, match))
					continue;
				if (entry.Refs is null)
					continue;
				foreach (var r in entry.Refs) {
					AddTarget(r.FuncName, r.FuncEa);
					if (targets.Count >= limit)
						break;
				}
			}

			return targets;
		}

		PseudocodeEnsureResult EnsurePseudocodeTargets(string analysisDir, IReadOnlyList<PseudocodeTarget> targets, bool caseSensitive, CancellationToken token) {
			var result = new PseudocodeEnsureResult();
			if (targets.Count == 0) {
				result.Success = true;
				return result;
			}

			var pseudocodePath = Path.Combine(analysisDir, "pseudocode.json");
			var existing = File.Exists(pseudocodePath) ? LoadPseudocode(pseudocodePath) : new List<PseudocodeEntry>();
			var missing = FilterMissingPseudocodeTargets(existing, targets, caseSensitive);
			result.Requested = targets.Count;

			if (missing.Count == 0) {
				result.Success = true;
				result.Exported = 0;
				result.OutputPath = pseudocodePath;
				return result;
			}

			var databasePath = FindIdaDatabase(analysisDir);
			if (string.IsNullOrWhiteSpace(databasePath)) {
				result.Error = "IDA database not found (expected .i64/.idb in analysis directory).";
				return result;
			}

			var scriptPath = IdaHeadlessRunner.GetExportPseudocodeScriptPath();
			if (!File.Exists(scriptPath)) {
				result.Error = $"Export script not found: {scriptPath}";
				return result;
			}
			var idaPath = config.IdaPath;
			if (string.IsNullOrWhiteSpace(idaPath)) {
				result.Error = "Missing idaPath (set kiln.config.json).";
				return result;
			}
			if (!File.Exists(idaPath)) {
				result.Error = $"idaPath not found: {idaPath}";
				return result;
			}

			var partialPath = Path.Combine(analysisDir, "pseudocode.partial.json");
			var names = missing.Where(t => !string.IsNullOrWhiteSpace(t.Name)).Select(t => t.Name!).ToList();
			var eas = missing.Where(t => !string.IsNullOrWhiteSpace(t.Ea)).Select(t => t.Ea!).ToList();
			var env = new Dictionary<string, string> {
				["KILN_EXPORT_OUTPUT"] = partialPath,
			};
			if (names.Count > 0)
				env["KILN_EXPORT_NAMES"] = JsonConvert.SerializeObject(names);
			if (eas.Count > 0)
				env["KILN_EXPORT_EAS"] = JsonConvert.SerializeObject(eas);

			IdaHeadlessRunner.CleanupUnpackedDatabase(databasePath);
			var export = IdaHeadlessRunner.RunAsync(
				idaPath,
				databasePath,
				analysisDir,
				scriptPath,
				null,
				token,
				null,
				env).GetAwaiter().GetResult();

			if (!export.Success) {
				result.Error = export.StdErr;
				return result;
			}

			var incoming = LoadPseudocode(partialPath);
			var merged = MergePseudocode(existing, incoming);
			SavePseudocodeJson(pseudocodePath, merged);
			RebuildPseudocodeIndexes(pseudocodePath, merged);
			result.Success = true;
			result.Exported = incoming.Count;
			result.OutputPath = pseudocodePath;
			return result;
		}

		List<PseudocodeTarget> FilterMissingPseudocodeTargets(List<PseudocodeEntry> existing, IReadOnlyList<PseudocodeTarget> targets, bool caseSensitive) {
			var existingEas = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			var existingNames = new HashSet<string>(caseSensitive ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase);

			foreach (var entry in existing) {
				if (!string.IsNullOrWhiteSpace(entry.Ea))
					existingEas.Add(NormalizeEa(entry.Ea));
				if (!string.IsNullOrWhiteSpace(entry.Name))
					existingNames.Add(caseSensitive ? entry.Name : entry.Name!.ToLowerInvariant());
			}

			var missing = new List<PseudocodeTarget>();
			var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
			foreach (var target in targets) {
				var normEa = NormalizeEa(target.Ea);
				var nameNorm = caseSensitive ? target.Name : target.Name?.ToLowerInvariant();
				if (!string.IsNullOrWhiteSpace(normEa) && existingEas.Contains(normEa))
					continue;
				if (!string.IsNullOrWhiteSpace(nameNorm) && existingNames.Contains(nameNorm))
					continue;

				var key = !string.IsNullOrWhiteSpace(normEa) ? "ea:" + normEa : "name:" + (nameNorm ?? string.Empty);
				if (seen.Add(key))
					missing.Add(target);
			}
			return missing;
		}

		List<PseudocodeEntry> MergePseudocode(List<PseudocodeEntry> existing, List<PseudocodeEntry> incoming) {
			var map = new Dictionary<string, PseudocodeEntry>(StringComparer.OrdinalIgnoreCase);
			foreach (var entry in existing) {
				var key = BuildPseudocodeKey(entry);
				if (!string.IsNullOrWhiteSpace(key))
					map[key] = entry;
			}
			foreach (var entry in incoming) {
				var key = BuildPseudocodeKey(entry);
				if (!string.IsNullOrWhiteSpace(key))
					map[key] = entry;
			}

			var list = map.Values.ToList();
			list.Sort((a, b) => {
				var left = TryParseEa(NormalizeEa(a.Ea));
				var right = TryParseEa(NormalizeEa(b.Ea));
				if (left.HasValue && right.HasValue)
					return left.Value.CompareTo(right.Value);
				if (left.HasValue)
					return -1;
				if (right.HasValue)
					return 1;
				return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
			});
			return list;
		}

		string BuildPseudocodeKey(PseudocodeEntry entry) {
			if (!string.IsNullOrWhiteSpace(entry.Ea))
				return "ea:" + NormalizeEa(entry.Ea);
			if (!string.IsNullOrWhiteSpace(entry.Name))
				return "name:" + entry.Name!.ToLowerInvariant();
			return string.Empty;
		}

		static ulong? TryParseEa(string? value) {
			if (string.IsNullOrWhiteSpace(value))
				return null;
			var text = value.Trim();
			if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
				text = text[2..];
			if (ulong.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
				return hex;
			if (ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec))
				return dec;
			return null;
		}

		void SavePseudocodeJson(string path, List<PseudocodeEntry> functions) {
			Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
			var items = new JArray();
			var anyFallback = false;
			var allFallback = true;
			foreach (var entry in functions) {
				var fallback = entry.Fallback;
				if (!string.IsNullOrWhiteSpace(fallback))
					anyFallback = true;
				else
					allFallback = false;
				items.Add(new JObject {
					["name"] = entry.Name,
					["ea"] = entry.Ea,
					["endEa"] = entry.EndEa,
					["size"] = entry.Size,
					["signature"] = entry.Signature,
					["pseudocode"] = entry.Pseudocode,
					["fallback"] = entry.Fallback,
					["truncated"] = entry.Truncated,
				});
			}

			var root = new JObject {
				["count"] = functions.Count,
				["functions"] = items,
			};
			if (anyFallback)
				root["fallbackMode"] = allFallback ? "disasm" : "mixed";
			File.WriteAllText(path, root.ToString(Formatting.Indented));
		}

		void RebuildPseudocodeIndexes(string pseudocodePath, List<PseudocodeEntry> functions) {
			var analysisDir = Path.GetDirectoryName(pseudocodePath) ?? ".";
			var localIndex = Path.Combine(analysisDir, "pseudocode.index.json");
			SavePseudocodeIndex(localIndex, functions);
			var cacheIndex = GetIndexCachePath(pseudocodePath, "pseudocode.index.json");
			if (!PathsEqual(localIndex, cacheIndex))
				SavePseudocodeIndex(cacheIndex, functions);
		}

		JobRecord? StartPseudocodeExportTargetsJob(string analysisDir, IReadOnlyList<PseudocodeTarget> targets, bool caseSensitive) {
			if (targets.Count == 0)
				return null;

			var paramsJson = new JObject {
				["analysisDir"] = analysisDir,
				["targets"] = new JArray(targets.Select(t => new JObject {
					["name"] = t.Name,
					["ea"] = t.Ea,
				})),
			}.ToString(Formatting.None);

			return jobManager.StartJob("ida.export.pseudocode.partial", paramsJson, context => {
				context.Update(JobState.Running, "export_pseudocode_partial", 5, null);
				context.Log($"Exporting pseudocode targets: {targets.Count}");

				var ensure = EnsurePseudocodeTargets(analysisDir, targets, caseSensitive, context.Token);
				if (!ensure.Success) {
					context.Log($"Pseudocode export failed: {ensure.Error ?? "unknown error"}");
					context.Update(JobState.Failed, "failed", 100, ensure.Error);
					return Task.CompletedTask;
				}

				context.Log($"Pseudocode export completed. Exported={ensure.Exported}");
				context.Update(JobState.Completed, "completed", 100, null);
				return Task.CompletedTask;
			});
		}

		JobRecord? StartPseudocodeExportAllJob(string analysisDir) {
			var databasePath = FindIdaDatabase(analysisDir);
			if (string.IsNullOrWhiteSpace(databasePath))
				return null;
			var scriptPath = IdaHeadlessRunner.GetExportPseudocodeScriptPath();
			if (!File.Exists(scriptPath))
				return null;

			var outputPath = Path.Combine(analysisDir, "pseudocode.json");
			var paramsJson = new JObject {
				["analysisDir"] = analysisDir,
				["outputPath"] = outputPath,
			}.ToString(Formatting.None);

			return jobManager.StartJob("ida.export.pseudocode", paramsJson, context => {
				context.Update(JobState.Running, "export_pseudocode", 5, null);
				context.Log($"Exporting pseudocode: {outputPath}");

				var result = RunIdaExport(config.IdaPath, databasePath, scriptPath, outputPath, null, context.Token);
				if (!result.Success) {
					context.Log($"Pseudocode export failed. ExitCode={result.ExitCode}");
					context.Update(JobState.Failed, "failed", 100, result.StdErr);
					return Task.CompletedTask;
				}

				var functions = LoadPseudocode(outputPath);
				RebuildPseudocodeIndexes(outputPath, functions);
				context.Log("Pseudocode export completed.");
				context.Update(JobState.Completed, "completed", 100, null);
				return Task.CompletedTask;
			});
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

		JobRecord? StartIdaExportJob(string flowName, string databasePath, string scriptPath, string outputPath, string? nameFilter, bool buildSymbolsIndex, bool buildPseudocodeIndex) {
			if (string.IsNullOrWhiteSpace(flowName))
				return null;

			var paramsJson = new JObject {
				["databasePath"] = databasePath,
				["outputPath"] = outputPath,
				["scriptPath"] = scriptPath,
				["nameFilter"] = nameFilter,
			}.ToString(Formatting.None);

			return jobManager.StartJob(flowName, paramsJson, context => {
				context.Update(JobState.Running, "export_ida", 5, null);
				context.Log($"IDA export started: {outputPath}");

				var result = RunIdaExport(config.IdaPath, databasePath, scriptPath, outputPath, nameFilter, context.Token);
				if (!result.Success) {
					context.Log($"IDA export failed. ExitCode={result.ExitCode}");
					context.Update(JobState.Failed, "failed", 100, result.StdErr);
					return Task.CompletedTask;
				}

				if (buildSymbolsIndex && File.Exists(outputPath)) {
					var symbols = LoadSymbols(outputPath);
					SaveSymbolsIndex(Path.Combine(Path.GetDirectoryName(outputPath) ?? ".", "symbols.index.json"), symbols);
				}
				if (buildPseudocodeIndex && File.Exists(outputPath)) {
					var functions = LoadPseudocode(outputPath);
					RebuildPseudocodeIndexes(outputPath, functions);
				}

				context.Log("IDA export completed.");
				context.Update(JobState.Completed, "completed", 100, null);
				return Task.CompletedTask;
			});
		}

		static IdaAnalyzeResult RunIdaExport(string? idaPath, string databasePath, string scriptPath, string outputPath, string? nameFilter) =>
			RunIdaExport(idaPath, databasePath, scriptPath, outputPath, nameFilter, CancellationToken.None);

		static IdaAnalyzeResult RunIdaExport(string? idaPath, string databasePath, string scriptPath, string outputPath, string? nameFilter, CancellationToken token) {
			if (string.IsNullOrWhiteSpace(idaPath))
				return new IdaAnalyzeResult(false, -1, databasePath, databasePath, string.Empty, string.Empty, "Missing idaPath.");
			if (!File.Exists(idaPath))
				return new IdaAnalyzeResult(false, -1, databasePath, databasePath, string.Empty, string.Empty, $"idaPath not found: {idaPath}");

			try {
				var env = new Dictionary<string, string> {
					["KILN_EXPORT_OUTPUT"] = outputPath,
				};
				if (!string.IsNullOrWhiteSpace(nameFilter))
					env["KILN_EXPORT_FILTER"] = nameFilter;
				IdaHeadlessRunner.CleanupUnpackedDatabase(databasePath);
				return IdaHeadlessRunner.RunAsync(
					idaPath,
					databasePath,
					Path.GetDirectoryName(databasePath) ?? string.Empty,
					scriptPath,
					null,
					token,
					null,
					env).GetAwaiter().GetResult();
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

		sealed class PseudocodeTarget {
			public string? Name { get; set; }
			public string? Ea { get; set; }
		}

		sealed class PseudocodeEnsureResult {
			public bool Success { get; set; }
			public int Requested { get; set; }
			public int Exported { get; set; }
			public string? OutputPath { get; set; }
			public string? Error { get; set; }
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
- Use resources/list and resources/read to load embedded docs (e.g. BepInEx).
- ida.* tools are proxied from ida-pro-mcp when enabled in kiln.config.json.";

		sealed class LiveFunctionInfo {
			public string Ea { get; set; } = string.Empty;
			public string Name { get; set; } = string.Empty;
			public long Size { get; set; }
			public int Score { get; set; }
		}

		sealed class PluginProjectResult {
			public bool Success { get; set; }
			public string ProjectDir { get; set; } = string.Empty;
			public string Runtime { get; set; } = string.Empty;
			public List<string> Files { get; } = new();
			public string? Error { get; set; }
		}

		PluginProjectResult CreatePluginProject(string gameDir, string? projectName, string? pluginGuid) {
			var result = new PluginProjectResult();
			if (string.IsNullOrWhiteSpace(gameDir)) {
				result.Error = "Missing gameDir.";
				return result;
			}
			if (string.IsNullOrWhiteSpace(config.ModsRoot)) {
				result.Error = "Missing modsRoot (set kiln.config.json).";
				return result;
			}

			var gameRoot = config.GetModsRootForGame(gameDir);
			Directory.CreateDirectory(gameRoot);
			var safeGameName = Path.GetFileName(gameRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
			if (string.IsNullOrWhiteSpace(safeGameName))
				safeGameName = "Game";

			var baseProjectName = string.IsNullOrWhiteSpace(projectName) ? $"{safeGameName}.Plugin" : projectName;
			var safeProjectName = MakeSafeFileName(baseProjectName);
			if (string.IsNullOrWhiteSpace(safeProjectName))
				safeProjectName = "Game.Plugin";

			var projectDir = Path.Combine(gameRoot, safeProjectName);
			if (Directory.Exists(projectDir)) {
				projectDir = Path.Combine(gameRoot, safeProjectName + "_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmmss"));
			}
			Directory.CreateDirectory(projectDir);

			var locate = UnityLocator.Locate(gameDir);
			var useIl2Cpp = locate.IsIl2Cpp || !locate.IsMono;
			var runtime = useIl2Cpp ? "IL2CPP" : "Mono";

			var ns = $"Kiln.Mods.{ToPascalIdentifier(safeGameName)}";
			var className = $"{ToPascalIdentifier(safeGameName)}Plugin";
			var guid = NormalizePluginGuid(pluginGuid, safeGameName);
			var displayName = $"{safeGameName} Plugin";
			var version = "1.0.0";

			var csprojPath = Path.Combine(projectDir, $"{safeProjectName}.csproj");
			var pluginPath = Path.Combine(projectDir, "Plugin.cs");
			var readmePath = Path.Combine(projectDir, "README.txt");

			File.WriteAllText(csprojPath, useIl2Cpp ? BuildIl2CppCsproj(safeProjectName) : BuildMonoCsproj(safeProjectName), Encoding.ASCII);
			File.WriteAllText(pluginPath, useIl2Cpp
				? BuildIl2CppPlugin(ns, className, guid, displayName, version)
				: BuildMonoPlugin(ns, className, guid, displayName, version), Encoding.ASCII);
			File.WriteAllText(readmePath, useIl2Cpp
				? BuildIl2CppReadme(safeProjectName)
				: BuildMonoReadme(safeProjectName), Encoding.ASCII);

			result.Success = true;
			result.ProjectDir = projectDir;
			result.Runtime = runtime;
			result.Files.Add(csprojPath);
			result.Files.Add(pluginPath);
			result.Files.Add(readmePath);
			return result;
		}

		static string BuildIl2CppCsproj(string projectName) {
			return string.Join(Environment.NewLine, new[] {
				"<Project Sdk=\"Microsoft.NET.Sdk\">",
				"  <PropertyGroup>",
				"    <TargetFramework>net6.0</TargetFramework>",
				$"    <AssemblyName>{projectName}</AssemblyName>",
				"    <Nullable>enable</Nullable>",
				"  </PropertyGroup>",
				"",
				"  <ItemGroup>",
				"    <PackageReference Include=\"BepInEx.Unity.IL2CPP\" Version=\"6.0.0-pre.1\" />",
				"    <PackageReference Include=\"BepInEx.PluginInfoProps\" Version=\"2.1.0\" PrivateAssets=\"all\" />",
				"  </ItemGroup>",
				"",
				"  <ItemGroup>",
				"    <Reference Include=\"Assembly-CSharp\">",
				"      <HintPath>$(BepInExUnhollowed)\\Assembly-CSharp.dll</HintPath>",
				"    </Reference>",
				"    <Reference Include=\"UnityEngine.CoreModule\">",
				"      <HintPath>$(BepInExUnhollowed)\\UnityEngine.CoreModule.dll</HintPath>",
				"    </Reference>",
				"  </ItemGroup>",
				"</Project>",
				string.Empty,
			});
		}

		static string BuildMonoCsproj(string projectName) {
			return string.Join(Environment.NewLine, new[] {
				"<Project Sdk=\"Microsoft.NET.Sdk\">",
				"  <PropertyGroup>",
				"    <TargetFramework>net6.0</TargetFramework>",
				$"    <AssemblyName>{projectName}</AssemblyName>",
				"    <Nullable>enable</Nullable>",
				"  </PropertyGroup>",
				"",
				"  <ItemGroup>",
				"    <PackageReference Include=\"BepInEx\" Version=\"5.4.23\" />",
				"    <PackageReference Include=\"BepInEx.PluginInfoProps\" Version=\"2.1.0\" PrivateAssets=\"all\" />",
				"  </ItemGroup>",
				"</Project>",
				string.Empty,
			});
		}

		static string BuildIl2CppPlugin(string ns, string className, string guid, string displayName, string version) {
			return string.Join(Environment.NewLine, new[] {
				"using BepInEx;",
				"using BepInEx.Unity.IL2CPP;",
				"using BepInEx.Logging;",
				"",
				$"namespace {ns}",
				"{",
				$"\t[BepInPlugin(\"{guid}\", \"{displayName}\", \"{version}\")]",
				$"\tpublic class {className} : BasePlugin",
				"\t{",
				"\t\tinternal static ManualLogSource Log;",
				"",
				"\t\tpublic override void Load()",
				"\t\t{",
				"\t\t\tLog = base.Log;",
				"\t\t\tLog.LogInfo(\"Plugin loaded.\");",
				"\t\t\t// TODO: call game SDK APIs here (prefer direct calls over patching).",
				"\t\t}",
				"\t}",
				"}",
				string.Empty,
			});
		}

		static string BuildMonoPlugin(string ns, string className, string guid, string displayName, string version) {
			return string.Join(Environment.NewLine, new[] {
				"using BepInEx;",
				"using BepInEx.Logging;",
				"",
				$"namespace {ns}",
				"{",
				$"\t[BepInPlugin(\"{guid}\", \"{displayName}\", \"{version}\")]",
				$"\tpublic class {className} : BaseUnityPlugin",
				"\t{",
				"\t\tinternal static ManualLogSource Log;",
				"",
				"\t\tprivate void Awake()",
				"\t\t{",
				"\t\t\tLog = Logger;",
				"\t\t\tLog.LogInfo(\"Plugin loaded.\");",
				"\t\t\t// TODO: call game SDK APIs here (prefer direct calls over patching).",
				"\t\t}",
				"\t}",
				"}",
				string.Empty,
			});
		}

		static string BuildIl2CppReadme(string projectName) {
			return string.Join(Environment.NewLine, new[] {
				projectName + " (IL2CPP)",
				"",
				"Build:",
				"  dotnet build -c Release -p:BepInExUnhollowed=\"D:\\Path\\To\\Game\\BepInEx\\unhollowed\"",
				"",
				"Install:",
				"  Copy bin\\Release\\net6.0\\" + projectName + ".dll to:",
				"  BepInEx\\plugins\\" + projectName + "\\",
				string.Empty,
			});
		}

		static string BuildMonoReadme(string projectName) {
			return string.Join(Environment.NewLine, new[] {
				projectName + " (Mono)",
				"",
				"Build:",
				"  dotnet build -c Release",
				"",
				"Install:",
				"  Copy bin\\Release\\net6.0\\" + projectName + ".dll to:",
				"  BepInEx\\plugins\\" + projectName + "\\",
				string.Empty,
			});
		}

		static string MakeSafeFileName(string value) {
			if (string.IsNullOrWhiteSpace(value))
				return string.Empty;
			var safe = value.Trim();
			foreach (var ch in Path.GetInvalidFileNameChars())
				safe = safe.Replace(ch, '_');
			return safe.Trim();
		}

		static string ToPascalIdentifier(string value) {
			if (string.IsNullOrWhiteSpace(value))
				return "Game";

			var chars = new List<char>(value.Length);
			var nextUpper = true;
			foreach (var ch in value) {
				if (char.IsLetterOrDigit(ch)) {
					var next = nextUpper ? char.ToUpperInvariant(ch) : char.ToLowerInvariant(ch);
					chars.Add(next);
					nextUpper = false;
				}
				else {
					nextUpper = true;
				}
			}

			var result = new string(chars.ToArray());
			if (string.IsNullOrWhiteSpace(result))
				result = "Game";
			if (char.IsDigit(result[0]))
				result = "Game" + result;
			return result;
		}

		static string NormalizePluginGuid(string? pluginGuid, string safeGameName) {
			if (!string.IsNullOrWhiteSpace(pluginGuid))
				return pluginGuid.Trim();

			var slugChars = new List<char>(safeGameName.Length);
			foreach (var ch in safeGameName) {
				if (char.IsLetterOrDigit(ch))
					slugChars.Add(char.ToLowerInvariant(ch));
				else
					slugChars.Add('.');
			}
			var slug = new string(slugChars.ToArray());
			var parts = slug.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
			slug = parts.Length == 0 ? "game" : string.Join(".", parts);
			return "com.kiln." + slug + ".plugin";
		}

		const string ExampleFlowText =
@"Kiln MCP example flow (detailed)

IMPORTANT
- You MUST call kiln.exampleFlow before using any other tool. The server enforces this.
- Read kiln.help for a short summary, then return here for full guidance.
- If ida-pro-mcp proxy is enabled, additional ida.* tools are available for real-time IDA queries.

Recommended end-to-end order (Unity IL2CPP):
detect_engine -> unity_locate -> il2cpp_dump (or manual dump) -> ida_analyze (or ida_register_db)
-> ida_export_symbols -> ida_export_pseudocode -> analysis.index.build -> analysis.* search
-> patch_codegen -> package_mod

Recommended live order (ida-pro-mcp):
ida.list_funcs -> ida.find -> ida.xrefs_to -> ida.decompile -> patch_codegen (analysisMode=live)
Notes:
- Live mode uses ida-pro-mcp tools and does not require offline exports.
- Offline exports remain available for large or repeatable analysis runs.

1) workflow.run (optional high-level flow)
Purpose: Run a predefined workflow (currently Unity IL2CPP pipeline).
Best practices:
- Use only for quick demos; step tools below give full control.
Common errors:
- Missing required params (flowName/gameDir).
Recommended order:
- Use at the start only if you want a single job.
Arguments:
{
  ""flowName"": ""unity.il2cpp"",
  ""params"": {
    ""gameDir"": ""C:\\Games\\Example"",
    ""outputDir"": ""C:\\Kiln\\output""
  }
}
Returns: { ""jobId"": ""..."" }

2) workflow.status
Purpose: Read job progress/stage/state.
Best practices:
- Poll this after workflow.run / ida_analyze.
Common errors:
- Unknown jobId (typo or expired job).
Recommended order:
- After workflow.run / ida_analyze.
Arguments: { ""jobId"": ""..."" }

3) workflow.logs
Purpose: Stream recent job log lines (headless tools print here).
Best practices:
- Use tail=200 for quick checks; bump for deeper diagnostics.
Common errors:
- Job not found or already cleaned up.
Recommended order:
- While workflow.status shows Running/Failed.
Arguments: { ""jobId"": ""..."", ""tail"": 200 }

4) workflow.cancel
Purpose: Stop a running job (best-effort).
Best practices:
- Call only when status=Running.
Common errors:
- Canceling a finished job does nothing.
Recommended order:
- Use if ida_analyze or dump hangs.
Arguments: { ""jobId"": ""..."" }

5) detect_engine
Purpose: Identify Unity/Mono/IL2CPP fingerprints in gameDir.
Best practices:
- Use before any Unity tools to confirm engine.
Common errors:
- Pointing to wrong folder (launcher root vs game root).
Recommended order:
- First step of the pipeline.
Args: { ""gameDir"": ""C:\\Games\\Example"" }

6) unity_locate
Purpose: Locate GameAssembly.dll / global-metadata.dat.
Best practices:
- Use after detect_engine for exact paths.
Common errors:
- Not IL2CPP build (no GameAssembly.dll).
Recommended order:
- Before il2cpp_dump or ida_analyze.
Args: { ""gameDir"": ""C:\\Games\\Example"" }

7) il2cpp_dump
Purpose: Run Il2CppDumper to create script.json + il2cpp.h.
Best practices:
- Keep Il2CppDumper and ida_with_struct_py3.py under il2cppRootDir.
- Let Kiln choose outputDir (il2cppRootDir/<game-name>).
Common errors:
- Output dir mismatch (Kiln enforces it).
- dumperPath not equal to il2cppRootDir or its Il2CppDumper.exe.
Recommended order:
- After unity_locate, before ida_analyze.
Args: { ""gameDir"": ""C:\\Games\\Example"" }

8) ida_analyze
Purpose: Run IDA headless analysis and auto-load Il2CppDumper symbols.
Best practices:
- Ensure script.json + il2cpp.h exist in il2cppRootDir/<game-name>.
- Prefer reuseExisting=true only when metadata matches.
Common errors:
- idaPath not matching kiln.config.json.
- Missing ida_with_struct_py3.py in il2cppRootDir.
Recommended order:
- After il2cpp_dump (or manual dump), before exports.
Args: { ""gameDir"": ""C:\\Games\\Example"", ""idaPath"": ""C:\\Program Files\\IDA Professional 9.2\\idat.exe"", ""reuseExisting"": true }

9) ida_register_db
Purpose: Import a pre-existing .i64/.idb into Kiln (no re-analysis).
Best practices:
- Use when you already analyzed and loaded symbols in IDA UI.
- Keep database path stable; enable copyToIdbDir for standard layout.
Common errors:
- Missing script.json/il2cpp.h under il2cppRootDir/<game-name>.
- databasePath not a .i64/.idb file.
Recommended order:
- Instead of ida_analyze when you already have a DB.
Args: { ""gameDir"": ""C:\\Games\\Example"", ""databasePath"": ""C:\\Tools\\GameAssembly.i64"", ""copyToIdbDir"": true, ""overwrite"": false }

10) ida_export_symbols
Purpose: Export functions, signatures, ranges, call graph, and strings.
Best practices:
- Run once per DB update; outputs symbols.json + strings.json.
Common errors:
- IDA DB not found in analysis directory.
Recommended order:
- After ida_analyze or ida_register_db.
Args: { ""jobId"": ""..."", ""async"": true }

11) ida_export_pseudocode
Purpose: Export pseudocode for functions (Hex-Rays).
Best practices:
- Use nameFilter for smaller exports.
Common errors:
- Hex-Rays missing; fallback becomes disassembly.
Recommended order:
- After ida_export_symbols, before analysis.search.
Args: { ""jobId"": ""..."", ""nameFilter"": ""Player"", ""async"": true }

12) analysis.index.build
Purpose: Build local + cached indexes (symbols, strings, pseudocode).
Best practices:
- Always run after exports for fast search.
Common errors:
- Missing symbols.json/pseudocode.json/strings.json.
Recommended order:
- After ida_export_symbols / ida_export_pseudocode.
Args: { ""jobId"": ""..."" }

13) analysis.symbols.search
Purpose: Search symbols by name/signature/address.
Best practices:
- Use field=signature when hunting types/method signatures.
Common errors:
- field not one of name|signature|ea.
Recommended order:
- After analysis.index.build.
Args: { ""jobId"": ""..."", ""query"": ""Player"", ""field"": ""name"", ""match"": ""contains"", ""limit"": 20, ""fields"": [""name"", ""ea"", ""signature""] }

14) analysis.symbols.get
Purpose: Fetch full symbol entry by name or address.
Best practices:
- Use ea for stable lookup when names are obfuscated.
Common errors:
- Passing both name and ea incorrectly.
Recommended order:
- After analysis.symbols.search.
Args: { ""jobId"": ""..."", ""name"": ""Player_Update"" }

15) analysis.symbols.xrefs
Purpose: Get callers/callees (call graph) for a function.
Best practices:
- Use direction=callers when tracing who invokes a target.
Common errors:
- Calling without name/ea.
Recommended order:
- After you identify a candidate symbol.
Args: { ""jobId"": ""..."", ""name"": ""Player_Update"", ""direction"": ""both"", ""limit"": 50 }

16) analysis.strings.search
Purpose: Search string literals and optionally return referencing functions.
Best practices:
- includeRefs=true to jump directly to functions.
Common errors:
- Missing strings.json (run ida_export_symbols first).
Recommended order:
- After analysis.index.build.
Args: { ""jobId"": ""..."", ""query"": ""weapon"", ""match"": ""contains"", ""includeRefs"": true, ""maxRefs"": 20 }

17) analysis.pseudocode.search
Purpose: Search pseudocode/disassembly text and return snippets.
Best practices:
- Use snippetChars to reduce token usage.
- autoExport=true will export missing pseudocode for likely candidates (background job).
- exportAll=true starts a background full export if nothing matches.
Common errors:
- No pseudocode export present.
Recommended order:
- After ida_export_pseudocode and analysis.index.build.
Args: { ""jobId"": ""..."", ""query"": ""weaponId"", ""limit"": 10, ""snippetChars"": 300, ""autoExport"": true, ""autoExportLimit"": 30 }

18) analysis.pseudocode.get
Purpose: Fetch full pseudocode/disassembly for a function.
Best practices:
- Use maxChars to avoid huge responses.
- autoExport=true will export the missing function on demand (returns pending + exportJobId).
Common errors:
- Target not found due to name mismatch.
Recommended order:
- After analysis.pseudocode.search or analysis.symbols.get.
Args: { ""jobId"": ""..."", ""name"": ""Player_Update"", ""maxChars"": 4000, ""autoExport"": true }

19) analysis.pseudocode.ensure
Purpose: Ensure pseudocode exists for specific functions (prefetch cache).
Best practices:
- Use after candidate search to pre-warm.
- exportAll=true starts a background full export (slow).
Common errors:
- Passing empty names/eas without exportAll.
Recommended order:
- After analysis.symbols.search / analysis.strings.search.
Args: { ""jobId"": ""..."", ""names"": [""Player_Update""], ""exportAll"": false, ""async"": true }

20) patch_codegen
Purpose: Generate mod/plugin template + target shortlist from analysis artifacts.
Best practices:
- Pass symbols/pseudocode/strings indexes for best results.
- You can pass jobId/gameDir/analysisDir and list filenames only; Kiln will resolve them.
- emitPluginProject=true generates a per-game plugin project under modsRoot.
Common errors:
- Empty artifacts => empty target list.
Recommended order:
- After analysis search identifies targets.
Args (offline): { ""jobId"": ""..."", ""requirements"": ""..."", ""analysisArtifacts"": [""symbols.json"", ""strings.json"", ""pseudocode.json""], ""emitPluginProject"": true }
Args (live): { ""requirements"": ""..."", ""analysisMode"": ""live"", ""databasePath"": ""D:\\\\Game\\\\Foo\\\\GameAssembly.i64"", ""autoStartIda"": true, ""liveMaxFunctions"": 200, ""liveMaxDecompile"": 40, ""emitPluginProject"": true }

21) package_mod
Purpose: Package output directory into zip with manifest/install/rollback.
Best practices:
- Run after patch_codegen outputs files.
Common errors:
- outputDir missing or empty.
Recommended order:
- Final step before distribution.
Args: { ""outputDir"": ""C:\\Kiln\\output"" }

22) MCP resources (BepInEx docs)
Purpose: Reference embedded docs (plugin structure, Harmony, IL2CPP).
Best practices:
- Read il2cpp-guide before writing patches.
Common errors:
- Unknown resource uri.
Recommended order:
- Anytime; helpful before patch_codegen.
- List resources: resources/list
- Read a resource: resources/read { ""uri"": ""bepinex://docs/il2cpp-guide"" }";
	}
}
