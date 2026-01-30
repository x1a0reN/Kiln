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
							["dumperPath"] = new JObject { ["type"] = "string" },
							["outputDir"] = new JObject { ["type"] = "string" },
						},
						["required"] = new JArray("gameDir", "dumperPath", "outputDir"),
						["additionalProperties"] = false,
					},
					"il2cpp_dump"),
				new ToolDef(
					"ida_analyze",
					"Run IDA headless analysis and apply symbols.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["gameDir"] = new JObject { ["type"] = "string" },
							["idaPath"] = new JObject { ["type"] = "string" },
							["idbDir"] = new JObject { ["type"] = "string" },
						},
						["required"] = new JArray("gameDir", "idaPath", "idbDir"),
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
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"ida_export_pseudocode"),
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
