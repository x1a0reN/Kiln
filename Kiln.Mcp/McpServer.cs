using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kiln.Core;
using Kiln.Plugins.Ida.Pro;
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
			if (tool.Method == "analysis.pseudocode.search")
				return HandleAnalysisPseudocodeSearch(id, input);
			if (tool.Method == "analysis.pseudocode.get")
				return HandleAnalysisPseudocodeGet(id, input);

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
			if (string.IsNullOrWhiteSpace(idbDir))
				idbDir = config.IdaOutputDir;
			if (string.IsNullOrWhiteSpace(idbDir))
				return ToolError(id, "Missing idbDir (set idaOutputDir in kiln.config.json).");

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

			var autoLoadScript = IdaHeadlessRunner.GetAutoLoadScriptPath();
			if (!File.Exists(autoLoadScript))
				return ToolError(id, $"Auto-load script not found: {autoLoadScript}");

			var locate = UnityLocator.Locate(gameDir);
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
			};
			return ToolOk(id, payload);
		}

		JObject HandleIdaExportSymbols(JToken? id, JObject input) {
			var jobId = input["jobId"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(jobId))
				return ToolError(id, "Missing jobId");

			if (!jobManager.TryGetStatus(jobId, out _))
				return ToolError(id, $"Unknown job: {jobId}");

			var jobDir = Path.Combine(config.WorkspaceRoot, jobId);
			var analysisDir = Path.Combine(jobDir, "ida");
			Directory.CreateDirectory(analysisDir);

			var databasePath = FindIdaDatabase(analysisDir);
			if (string.IsNullOrWhiteSpace(databasePath))
				return ToolError(id, "IDA database not found (expected .i64/.idb in workspace/job/ida).");

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

			var jobDir = Path.Combine(config.WorkspaceRoot, jobId);
			var analysisDir = Path.Combine(jobDir, "ida");
			Directory.CreateDirectory(analysisDir);

			var databasePath = FindIdaDatabase(analysisDir);
			if (string.IsNullOrWhiteSpace(databasePath))
				return ToolError(id, "IDA database not found (expected .i64/.idb in workspace/job/ida).");

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
			var result = new JObject();

			if (File.Exists(symbolsPath)) {
				var symbols = LoadSymbols(symbolsPath);
				var indexPath = Path.Combine(analysisDir, "symbols.index.json");
				SaveSymbolsIndex(indexPath, symbols);
				result["symbolsIndex"] = indexPath;
				result["symbolsCount"] = symbols.Count;
			}
			else {
				result["symbolsIndex"] = null;
			}

			if (File.Exists(pseudocodePath)) {
				var functions = LoadPseudocode(pseudocodePath);
				var indexPath = Path.Combine(analysisDir, "pseudocode.index.json");
				SavePseudocodeIndex(indexPath, functions);
				result["pseudocodeIndex"] = indexPath;
				result["pseudocodeCount"] = functions.Count;
			}
			else {
				result["pseudocodeIndex"] = null;
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
			var match = input["match"]?.Value<string>() ?? "contains";
			var caseSensitive = input["caseSensitive"]?.Value<bool?>() ?? false;
			var limit = Math.Clamp(input["limit"]?.Value<int?>() ?? 20, 1, 200);
			var offset = Math.Max(0, input["offset"]?.Value<int?>() ?? 0);
			var fields = input["fields"] as JArray;

			var queryNorm = caseSensitive ? query : query!.ToLowerInvariant();
			var results = new List<JObject>();
			var total = 0;

			for (var i = 0; i < list.Count; i++) {
				var entry = list[i];
				var name = entry.Name ?? string.Empty;
				var nameNorm = caseSensitive ? name : (entry.NameLower ?? name.ToLowerInvariant());
				if (!IsMatch(nameNorm, queryNorm, match))
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
					if (string.Equals(entry.Ea, ea, StringComparison.OrdinalIgnoreCase))
						return ToolOk(id, SelectSymbolFields(entry, null));
				}
			}

			return ToolError(id, "Symbol not found.");
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
					["pseudocode"] = text,
					["truncated"] = truncated,
				};
				return ToolOk(id, payload);
			}

			return ToolError(id, "Pseudocode not found.");
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

		static List<SymbolEntry> LoadSymbolsPreferIndex(string analysisDir) {
			var indexPath = Path.Combine(analysisDir, "symbols.index.json");
			var symbolsPath = Path.Combine(analysisDir, "symbols.json");
			if (File.Exists(indexPath))
				return LoadSymbols(indexPath);
			return LoadSymbols(symbolsPath);
		}

		static List<PseudocodeEntry> LoadPseudocodePreferIndex(string analysisDir) {
			var indexPath = Path.Combine(analysisDir, "pseudocode.index.json");
			var pseudocodePath = Path.Combine(analysisDir, "pseudocode.json");
			if (File.Exists(indexPath))
				return LoadPseudocode(indexPath);
			return LoadPseudocode(pseudocodePath);
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
				list.Add(new SymbolEntry {
					Name = obj["name"]?.Value<string>() ?? string.Empty,
					NameLower = obj["nameLower"]?.Value<string>(),
					Ea = obj["ea"]?.Value<string>() ?? string.Empty,
					Signature = obj["signature"]?.Value<string>(),
					Segment = obj["segment"]?.Value<string>(),
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
					Pseudocode = obj["pseudocode"]?.Value<string>() ?? string.Empty,
					PseudocodeLower = obj["pseudocodeLower"]?.Value<string>(),
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
					["signature"] = entry.Signature,
					["segment"] = entry.Segment,
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
					["pseudocode"] = code,
					["pseudocodeLower"] = code.ToLowerInvariant(),
				});
			}

			var root = new JObject {
				["count"] = functions.Count,
				["functions"] = items,
			};
			File.WriteAllText(path, root.ToString(Formatting.Indented));
		}

		static JObject SelectSymbolFields(SymbolEntry entry, JArray? fields) {
			if (fields is null || fields.Count == 0) {
				return new JObject {
					["name"] = entry.Name,
					["ea"] = entry.Ea,
					["signature"] = entry.Signature,
					["segment"] = entry.Segment,
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
					case "signature":
						obj["signature"] = entry.Signature;
						break;
					case "segment":
						obj["segment"] = entry.Segment;
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

		sealed class SymbolEntry {
			public string Name { get; set; } = string.Empty;
			public string? NameLower { get; set; }
			public string Ea { get; set; } = string.Empty;
			public string? Signature { get; set; }
			public string? Segment { get; set; }
		}

		sealed class PseudocodeEntry {
			public string Name { get; set; } = string.Empty;
			public string? NameLower { get; set; }
			public string Ea { get; set; } = string.Empty;
			public string? Pseudocode { get; set; }
			public string? PseudocodeLower { get; set; }
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

1) Run a workflow
Tool: workflow.run
Arguments:
{
  ""flowName"": ""unity.il2cpp"",
  ""params"": {
    ""gameDir"": ""C:\\Games\\Example"",
    ""outputDir"": ""C:\\Kiln\\output""
  }
}
Returns: { ""jobId"": ""..."" }

2) Check status
Tool: workflow.status
Arguments: { ""jobId"": ""..."" }
Returns: { ""percent"": 0-100, ""stage"": ""..."", ""state"": ""Running|Completed|Failed"" }

3) Tail logs
Tool: workflow.logs
Arguments: { ""jobId"": ""..."", ""tail"": 200 }

4) Cancel
Tool: workflow.cancel
Arguments: { ""jobId"": ""..."" }

5) Step tools (advanced users)
- detect_engine
  { ""gameDir"": ""C:\\Games\\Example"" }
- unity_locate
  { ""gameDir"": ""C:\\Games\\Example"" }
- il2cpp_dump
  { ""gameDir"": ""C:\\Games\\Example"", ""dumperPath"": ""C:\\Kiln\\Il2CppDumper"" }
- ida_analyze
  { ""gameDir"": ""C:\\Games\\Example"", ""idaPath"": ""C:\\Program Files\\IDA Professional 9.2\\idat64.exe"" }
- ida_export_symbols
  { ""jobId"": ""..."" }
- ida_export_pseudocode
  { ""jobId"": ""..."", ""nameFilter"": ""Player"" }
- analysis.index.build
  { ""jobId"": ""..."" }
- analysis.symbols.search
  { ""jobId"": ""..."", ""query"": ""Player"", ""match"": ""contains"", ""limit"": 20 }
- analysis.symbols.get
  { ""jobId"": ""..."", ""name"": ""Player_Update"" }
- analysis.pseudocode.search
  { ""jobId"": ""..."", ""query"": ""weaponId"", ""limit"": 10, ""snippetChars"": 300 }
- analysis.pseudocode.get
  { ""jobId"": ""..."", ""name"": ""Player_Update"", ""maxChars"": 4000 }
- patch_codegen
  { ""requirements"": ""..."", ""analysisArtifacts"": [""...""] }
- package_mod
  { ""outputDir"": ""C:\\Kiln\\output"" }

6) MCP resources (BepInEx docs)
- List resources: resources/list
- Read a resource: resources/read { ""uri"": ""bepinex://docs/il2cpp-guide"" }";
	}
}
