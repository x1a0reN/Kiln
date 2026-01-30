using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kiln.Core;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kiln.Mcp {
	sealed class McpServer {
		readonly ToolCatalog catalog;
		readonly ResourceCatalog resources;
		readonly JobManager jobManager;

		public McpServer(JobManager jobManager) {
			this.jobManager = jobManager ?? throw new ArgumentNullException(nameof(jobManager));
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
  { ""gameDir"": ""C:\\Games\\Example"", ""dumperPath"": ""C:\\Tools\\Il2CppDumper"", ""outputDir"": ""C:\\Kiln\\work\\dump"" }
- ida_analyze
  { ""gameDir"": ""C:\\Games\\Example"", ""idaPath"": ""C:\\Program Files\\IDA Professional 9.2\\idat64.exe"", ""idbDir"": ""C:\\Kiln\\work\\ida"" }
- ida_export_symbols
  { ""jobId"": ""..."" }
- ida_export_pseudocode
  { ""jobId"": ""..."" }
- patch_codegen
  { ""requirements"": ""..."", ""analysisArtifacts"": [""...""] }
- package_mod
  { ""outputDir"": ""C:\\Kiln\\output"" }

6) MCP resources (BepInEx docs)
- List resources: resources/list
- Read a resource: resources/read { ""uri"": ""bepinex://docs/il2cpp-guide"" }";
	}
}
