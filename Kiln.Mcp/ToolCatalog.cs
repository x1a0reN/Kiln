using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace Kiln.Mcp {
	sealed class ToolCatalog {
		public IReadOnlyDictionary<string, ToolDef> Tools { get; }

		public ToolCatalog() {
			var list = new List<ToolDef> {
				new ToolDef(
					"kiln.help",
					"Describe Kiln MCP tools and tips (see kiln.exampleFlow for detailed usage).",
					EmptySchema(),
					"__local.help"),
				new ToolDef(
					"kiln.exampleFlow",
					"Detailed usage examples for all Kiln MCP tools (recommended first read).",
					EmptySchema(),
					"__local.exampleFlow"),
				new ToolDef(
					"workflow.run",
					"Run a workflow and return a job id.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["flowName"] = new JObject { ["type"] = "string" },
							["params"] = new JObject { ["type"] = "object" },
						},
						["required"] = new JArray("flowName"),
						["additionalProperties"] = false,
					},
					"workflow.run"),
				new ToolDef(
					"workflow.status",
					"Get status and progress for a job id.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"workflow.status"),
				new ToolDef(
					"workflow.logs",
					"Tail job logs.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["tail"] = new JObject { ["type"] = "integer" },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"workflow.logs"),
				new ToolDef(
					"workflow.cancel",
					"Cancel a running job.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"workflow.cancel"),
				new ToolDef(
					"detect_engine",
					"Detect engine and runtime for a game directory.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["gameDir"] = new JObject { ["type"] = "string" },
						},
						["required"] = new JArray("gameDir"),
						["additionalProperties"] = false,
					},
					"detect_engine"),
				new ToolDef(
					"unity_locate",
					"Locate Unity IL2CPP artifacts (GameAssembly.dll, metadata).",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["gameDir"] = new JObject { ["type"] = "string" },
						},
						["required"] = new JArray("gameDir"),
						["additionalProperties"] = false,
					},
					"unity_locate"),
				new ToolDef(
					"il2cpp_dump",
					"Run Il2CppDumper to generate metadata and headers.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["gameDir"] = new JObject { ["type"] = "string" },
							["dumperPath"] = new JObject { ["type"] = "string", ["description"] = "Optional; must match il2cppRootDir or Il2CppDumper.exe inside it." },
							["outputDir"] = new JObject { ["type"] = "string", ["description"] = "Optional; defaults to il2cppRootDir/<game-name> (must match if provided)." },
						},
						["required"] = new JArray("gameDir"),
						["additionalProperties"] = false,
					},
					"il2cpp_dump"),
				new ToolDef(
					"ida_analyze",
					"Run IDA headless analysis and apply symbols/types (auto-load).",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["gameDir"] = new JObject { ["type"] = "string" },
							["idaPath"] = new JObject { ["type"] = "string", ["description"] = "Required; must match kiln.config.json (idaPath)." },
							["idbDir"] = new JObject { ["type"] = "string", ["description"] = "Optional; defaults to idaOutputDir in kiln.config.json." },
							["scriptPath"] = new JObject { ["type"] = "string", ["description"] = "Optional; must match ida_with_struct_py3.py inside il2cppRootDir." },
						},
						["required"] = new JArray("gameDir", "idaPath"),
						["additionalProperties"] = false,
					},
					"ida_analyze"),
				new ToolDef(
					"ida_export_symbols",
					"Export function list and signatures from IDA.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["outputPath"] = new JObject { ["type"] = "string", ["description"] = "Optional; defaults to idaOutputDir/symbols.json." },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"ida_export_symbols"),
				new ToolDef(
					"ida_export_pseudocode",
					"Export Hex-Rays pseudocode from IDA.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["nameFilter"] = new JObject { ["type"] = "string", ["description"] = "Optional; only export functions containing this substring." },
							["outputPath"] = new JObject { ["type"] = "string", ["description"] = "Optional; defaults to idaOutputDir/pseudocode.json." },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"ida_export_pseudocode"),
				new ToolDef(
					"analysis.index.build",
					"Build local indexes for symbols and pseudocode exports.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"analysis.index.build"),
				new ToolDef(
					"analysis.symbols.search",
					"Search exported symbols by name.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["query"] = new JObject { ["type"] = "string" },
							["match"] = new JObject { ["type"] = "string", ["description"] = "exact|contains" },
							["caseSensitive"] = new JObject { ["type"] = "boolean" },
							["limit"] = new JObject { ["type"] = "integer" },
							["offset"] = new JObject { ["type"] = "integer" },
							["fields"] = new JObject {
								["type"] = "array",
								["items"] = new JObject { ["type"] = "string" },
							},
						},
						["required"] = new JArray("jobId", "query"),
						["additionalProperties"] = false,
					},
					"analysis.symbols.search"),
				new ToolDef(
					"analysis.symbols.get",
					"Get a symbol by name or address.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["name"] = new JObject { ["type"] = "string" },
							["ea"] = new JObject { ["type"] = "string" },
							["caseSensitive"] = new JObject { ["type"] = "boolean" },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"analysis.symbols.get"),
				new ToolDef(
					"analysis.pseudocode.search",
					"Search in exported pseudocode and return snippets.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["query"] = new JObject { ["type"] = "string" },
							["match"] = new JObject { ["type"] = "string", ["description"] = "exact|contains" },
							["caseSensitive"] = new JObject { ["type"] = "boolean" },
							["limit"] = new JObject { ["type"] = "integer" },
							["snippetChars"] = new JObject { ["type"] = "integer" },
						},
						["required"] = new JArray("jobId", "query"),
						["additionalProperties"] = false,
					},
					"analysis.pseudocode.search"),
				new ToolDef(
					"analysis.pseudocode.get",
					"Get pseudocode for a function by name or address.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["name"] = new JObject { ["type"] = "string" },
							["ea"] = new JObject { ["type"] = "string" },
							["caseSensitive"] = new JObject { ["type"] = "boolean" },
							["maxChars"] = new JObject { ["type"] = "integer" },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"analysis.pseudocode.get"),
				new ToolDef(
					"patch_codegen",
					"Generate patch/plugin template from requirements and analysis artifacts.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["requirements"] = new JObject { ["type"] = "string" },
							["analysisArtifacts"] = new JObject {
								["type"] = "array",
								["items"] = new JObject { ["type"] = "string" },
							},
						},
						["required"] = new JArray("requirements"),
						["additionalProperties"] = false,
					},
					"patch_codegen"),
				new ToolDef(
					"package_mod",
					"Package output artifacts and installation guide.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["outputDir"] = new JObject { ["type"] = "string" },
						},
						["required"] = new JArray("outputDir"),
						["additionalProperties"] = false,
					},
					"package_mod"),
			};

			var map = new Dictionary<string, ToolDef>();
			foreach (var tool in list)
				map[tool.Name] = tool;
			Tools = map;
		}

		static JObject EmptySchema() {
			return new JObject {
				["type"] = "object",
				["properties"] = new JObject(),
				["additionalProperties"] = false,
			};
		}
	}

	sealed class ToolDef {
		public string Name { get; }
		public string Description { get; }
		public JObject InputSchema { get; }
		public string Method { get; }

		public ToolDef(string name, string description, JObject inputSchema, string method) {
			Name = name;
			Description = description;
			InputSchema = inputSchema;
			Method = method;
		}
	}
}
