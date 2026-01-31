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
							["reuseExisting"] = new JObject { ["type"] = "boolean", ["description"] = "Optional; reuse existing .i64/.idb in idbDir (default true)." },
						},
						["required"] = new JArray("gameDir", "idaPath"),
						["additionalProperties"] = false,
					},
					"ida_analyze"),
				new ToolDef(
					"ida_register_db",
					"Register an existing IDA database (.i64/.idb) for reuse.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["gameDir"] = new JObject { ["type"] = "string" },
							["databasePath"] = new JObject { ["type"] = "string" },
							["idbDir"] = new JObject { ["type"] = "string", ["description"] = "Optional; override output directory for this game." },
							["copyToIdbDir"] = new JObject { ["type"] = "boolean", ["description"] = "Optional; copy DB into idbDir (default true)." },
							["overwrite"] = new JObject { ["type"] = "boolean", ["description"] = "Optional; overwrite existing DB (default false)." },
						},
						["required"] = new JArray("gameDir", "databasePath"),
						["additionalProperties"] = false,
					},
					"ida_register_db"),
				new ToolDef(
					"ida_export_symbols",
					"Export function list and signatures from IDA.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["outputPath"] = new JObject { ["type"] = "string", ["description"] = "Optional; defaults to idaOutputDir/symbols.json." },
							["async"] = new JObject { ["type"] = "boolean", ["description"] = "Optional; run export as background job (default true)." },
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
							["async"] = new JObject { ["type"] = "boolean", ["description"] = "Optional; run export as background job (default true)." },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"ida_export_pseudocode"),
				new ToolDef(
					"analysis.index.build",
					"Build local indexes for symbols, strings, and pseudocode exports.",
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
					"Search exported symbols by name, signature, or address.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["query"] = new JObject { ["type"] = "string" },
							["field"] = new JObject { ["type"] = "string", ["description"] = "name|signature|ea" },
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
					"analysis.symbols.xrefs",
					"Get callers/callees for a function.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["name"] = new JObject { ["type"] = "string" },
							["ea"] = new JObject { ["type"] = "string" },
							["caseSensitive"] = new JObject { ["type"] = "boolean" },
							["direction"] = new JObject { ["type"] = "string", ["description"] = "callers|callees|both" },
							["limit"] = new JObject { ["type"] = "integer" },
							["offset"] = new JObject { ["type"] = "integer" },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"analysis.symbols.xrefs"),
				new ToolDef(
					"analysis.strings.search",
					"Search exported strings and optionally return function references.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["query"] = new JObject { ["type"] = "string" },
							["match"] = new JObject { ["type"] = "string", ["description"] = "exact|contains" },
							["caseSensitive"] = new JObject { ["type"] = "boolean" },
							["limit"] = new JObject { ["type"] = "integer" },
							["offset"] = new JObject { ["type"] = "integer" },
							["includeRefs"] = new JObject { ["type"] = "boolean" },
							["maxRefs"] = new JObject { ["type"] = "integer" },
						},
						["required"] = new JArray("jobId", "query"),
						["additionalProperties"] = false,
					},
					"analysis.strings.search"),
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
							["autoExport"] = new JObject { ["type"] = "boolean", ["description"] = "Optional; auto-export missing pseudocode in background (default true)." },
							["autoExportLimit"] = new JObject { ["type"] = "integer", ["description"] = "Optional; cap auto-export targets (default 30)." },
							["exportAll"] = new JObject { ["type"] = "boolean", ["description"] = "Optional; start background full export if no match (default false)." },
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
							["autoExport"] = new JObject { ["type"] = "boolean", ["description"] = "Optional; auto-export missing pseudocode in background (default true)." },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"analysis.pseudocode.get"),
				new ToolDef(
					"analysis.pseudocode.ensure",
					"Ensure pseudocode exists for specific functions (export-on-demand, optional full export).",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string" },
							["names"] = new JObject {
								["type"] = "array",
								["items"] = new JObject { ["type"] = "string" },
							},
							["eas"] = new JObject {
								["type"] = "array",
								["items"] = new JObject { ["type"] = "string" },
							},
							["caseSensitive"] = new JObject { ["type"] = "boolean" },
							["maxTargets"] = new JObject { ["type"] = "integer", ["description"] = "Optional; cap target count (default 50)." },
							["exportAll"] = new JObject { ["type"] = "boolean", ["description"] = "Optional; start background full export (default false)." },
							["async"] = new JObject { ["type"] = "boolean", ["description"] = "Optional; run export as background job (default true)." },
						},
						["required"] = new JArray("jobId"),
						["additionalProperties"] = false,
					},
					"analysis.pseudocode.ensure"),
				new ToolDef(
					"patch_codegen",
					"Generate mod/plugin template from requirements and analysis artifacts.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["jobId"] = new JObject { ["type"] = "string", ["description"] = "Optional; resolve artifacts from the job's analysis directory." },
							["gameDir"] = new JObject { ["type"] = "string", ["description"] = "Optional; resolve artifacts from idaOutputDir/<game-name>." },
							["analysisDir"] = new JObject { ["type"] = "string", ["description"] = "Optional; resolve artifacts relative to this analysis directory." },
							["requirements"] = new JObject { ["type"] = "string" },
							["emitPluginProject"] = new JObject { ["type"] = "boolean", ["description"] = "Optional; auto-generate per-game plugin project under modsRoot (default true)." },
							["projectName"] = new JObject { ["type"] = "string", ["description"] = "Optional; override generated plugin project name." },
							["pluginGuid"] = new JObject { ["type"] = "string", ["description"] = "Optional; override BepInEx plugin GUID." },
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
