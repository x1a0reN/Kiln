using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace dnSpyEx.MCP.Bridge {
	sealed class McpServer {
		readonly PipeClient pipe;
		readonly ToolCatalog catalog;

		public McpServer(PipeClient pipe) {
			this.pipe = pipe ?? throw new ArgumentNullException(nameof(pipe));
			catalog = new ToolCatalog();
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
					BridgeLog.Warn("stdio parse error");
					await WriteResponseAsync(MakeError(null, -32700, "Parse error")).ConfigureAwait(false);
					continue;
				}

				BridgeLog.Info($"stdio request: {request["method"]?.Value<string>() ?? "(null)"}");
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
				},
				["serverInfo"] = new JObject {
					["name"] = "dnSpyEx.MCP.Bridge",
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

		async Task<JObject> ToolsCallAsync(JObject request, JToken? id, CancellationToken token) {
			var args = request["params"] as JObject;
			var name = args?["name"]?.Value<string>();
			var input = args?["arguments"] as JObject ?? new JObject();
			if (string.IsNullOrWhiteSpace(name))
				return MakeError(id, -32602, "Missing tool name");

			if (!catalog.Tools.TryGetValue(name, out var tool))
				return MakeError(id, -32601, $"Unknown tool: {name}");

			BridgeLog.Info($"tool call: {name}");
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

			var rpcReq = new JObject {
				["jsonrpc"] = "2.0",
				["id"] = Guid.NewGuid().ToString("N"),
				["method"] = tool.Method,
				["params"] = input,
			};

			JObject rpcResp;
			try {
				rpcResp = await pipe.CallAsync(rpcReq, token).ConfigureAwait(false);
			}
			catch (Exception ex) {
				return ToolError(id, $"IPC error: {ex.Message}");
			}

			var error = rpcResp["error"] as JObject;
			if (error is not null)
				return ToolError(id, error["message"]?.Value<string>() ?? "IPC error");

			var result = rpcResp["result"];
			var text = result is null ? string.Empty : result.ToString(Formatting.Indented);
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
@"dnSpyEx MCP tools (quick guide)

Read first:
- dnspy.exampleFlow (full usage examples)

Common flow:
1) dnspy.listAssemblies -> pick moduleMvid
2) dnspy.listNamespaces(moduleMvid) -> choose namespace ("" = global)
3) dnspy.listTypes(moduleMvid, namespace) -> pick typeToken
4) dnspy.listMembers(moduleMvid, typeToken) -> pick member token
5) dnspy.decompileMethod / dnspy.decompileField / dnspy.decompileProperty / dnspy.decompileEvent

Notes:
- namespace parameter can be empty string for global namespace.
- token/typeToken are uint metadata tokens from listTypes/listMembers.
- dnspy.decompile only supports method|field|property|event (no full type output).";

		const string ExampleFlowText =
@"dnSpyEx MCP example flow (detailed)

0) Read the docs tools
- dnspy.exampleFlow: full usage examples (this text).
- dnspy.help: short summary and tips.

1) List modules
Tool: dnspy.listAssemblies
Arguments: {}
Returns: array of modules with moduleMvid, moduleName, assemblyName, filename.

2) List namespaces in a module
Tool: dnspy.listNamespaces
Arguments:
{ ""moduleMvid"": ""<GUID>"" }
Note: global namespace is returned as empty string """".

3) List types in a namespace (including global)
Tool: dnspy.listTypes
Arguments:
{ ""moduleMvid"": ""<GUID>"", ""namespace"": ""My.Namespace"" }
Global namespace example:
{ ""moduleMvid"": ""<GUID>"", ""namespace"": """" }
Returns: array of types with token and fullName.

4) List members in a type
Tool: dnspy.listMembers
Arguments:
{ ""moduleMvid"": ""<GUID>"", ""typeToken"": 33554433 }
Returns: methods/fields/properties/events with token.

5) Decompile (method/field/property/event only)
Tools:
- dnspy.decompileMethod
  { ""moduleMvid"": ""<GUID>"", ""token"": 100663297 }
- dnspy.decompileField
  { ""moduleMvid"": ""<GUID>"", ""token"": 67108865 }
- dnspy.decompileProperty
  { ""moduleMvid"": ""<GUID>"", ""token"": 385875968 }
- dnspy.decompileEvent
  { ""moduleMvid"": ""<GUID>"", ""token"": 536870912 }
- dnspy.decompile (kind = method|field|property|event)
  { ""kind"": ""method"", ""moduleMvid"": ""<GUID>"", ""token"": 100663297 }

6) Field / enum / struct / interface info
- dnspy.getFieldInfo
  { ""moduleMvid"": ""<GUID>"", ""token"": 67108865 }
- dnspy.getEnumInfo
  { ""moduleMvid"": ""<GUID>"", ""typeToken"": 33554433 }
- dnspy.getStructInfo
  { ""moduleMvid"": ""<GUID>"", ""typeToken"": 33554433 }
- dnspy.getInterfaceInfo
  { ""moduleMvid"": ""<GUID>"", ""typeToken"": 33554433 }

7) Search (full dnSpyEx search settings)
Tool: dnspy.search
Arguments (minimal):
{ ""searchText"": ""Player"" }
Arguments (full example):
{
  ""searchText"": ""Player"",
  ""searchType"": ""type"",
  ""searchLocation"": ""allFiles"",
  ""caseSensitive"": false,
  ""matchWholeWords"": false,
  ""matchAnySearchTerm"": false,
  ""searchDecompiledData"": true,
  ""searchFrameworkAssemblies"": true,
  ""searchCompilerGeneratedMembers"": true,
  ""syntaxHighlight"": true,
  ""maxResults"": 5000
}

8) Get selected text
Tool: dnspy.getSelectedText
Arguments: {}
Returns: hasViewer, isEmpty, caretPosition, text.

Tips:
- Always call dnspy.exampleFlow first for full examples.
- Use moduleMvid + token/typeToken from previous list calls.";
	}
}
