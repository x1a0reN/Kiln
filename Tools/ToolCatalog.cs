using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace dnSpyEx.MCP.Bridge {
	sealed class ToolCatalog {
		public IReadOnlyDictionary<string, ToolDef> Tools { get; }

		public ToolCatalog() {
			var list = new List<ToolDef> {
				new ToolDef(
					"dnspy.help",
					"Describe dnSpyEx MCP tools and tips (see dnspy.exampleFlow for detailed usage).",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject(),
						["additionalProperties"] = false,
					},
					"__local.help"),
				new ToolDef(
					"dnspy.exampleFlow",
					"Detailed usage examples for all dnSpyEx MCP tools (recommended first read).",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject(),
						["additionalProperties"] = false,
					},
					"__local.exampleFlow"),
				new ToolDef(
					"dnspy.listAssemblies",
					"List loaded assemblies and modules. See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject(),
						["additionalProperties"] = false,
					},
					"listAssemblies"),
				new ToolDef(
					"dnspy.listNamespaces",
					"List namespaces in a module. See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
						},
						["required"] = new JArray("moduleMvid"),
						["additionalProperties"] = false,
					},
					"listNamespaces"),
				new ToolDef(
					"dnspy.listTypes",
					"List types in a module namespace (use empty string for global namespace). See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
							["namespace"] = new JObject {
								["type"] = "string",
								["description"] = "Namespace (empty string for global)",
							},
						},
						["required"] = new JArray("moduleMvid", "namespace"),
						["additionalProperties"] = false,
					},
					"listTypes"),
				new ToolDef(
					"dnspy.listMembers",
					"List members in a type. See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
							["typeToken"] = new JObject {
								["type"] = "integer",
								["description"] = "Type MD token (uint)",
							},
						},
						["required"] = new JArray("moduleMvid", "typeToken"),
						["additionalProperties"] = false,
					},
					"listMembers"),
				new ToolDef(
					"dnspy.decompile",
					"Decompile a method/field/property/event only (no full type output). See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["kind"] = new JObject {
								["type"] = "string",
								["description"] = "method|field|property|event",
							},
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
							["namespace"] = new JObject {
								["type"] = "string",
								["description"] = "Namespace (for kind=namespace)",
							},
							["token"] = new JObject {
								["type"] = "integer",
								["description"] = "Member MD token (for kind=type/method/field/property/event)",
							},
						},
						["required"] = new JArray("kind", "moduleMvid"),
						["additionalProperties"] = false,
					},
					"decompile"),
				new ToolDef(
					"dnspy.decompileMethod",
					"Decompile a single method. See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
							["token"] = new JObject {
								["type"] = "integer",
								["description"] = "Method MD token (uint)",
							},
						},
						["required"] = new JArray("moduleMvid", "token"),
						["additionalProperties"] = false,
					},
					"decompileMethod"),
				new ToolDef(
					"dnspy.decompileField",
					"Decompile a single field. See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
							["token"] = new JObject {
								["type"] = "integer",
								["description"] = "Field MD token (uint)",
							},
						},
						["required"] = new JArray("moduleMvid", "token"),
						["additionalProperties"] = false,
					},
					"decompileField"),
				new ToolDef(
					"dnspy.decompileProperty",
					"Decompile a single property. See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
							["token"] = new JObject {
								["type"] = "integer",
								["description"] = "Property MD token (uint)",
							},
						},
						["required"] = new JArray("moduleMvid", "token"),
						["additionalProperties"] = false,
					},
					"decompileProperty"),
				new ToolDef(
					"dnspy.decompileEvent",
					"Decompile a single event. See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
							["token"] = new JObject {
								["type"] = "integer",
								["description"] = "Event MD token (uint)",
							},
						},
						["required"] = new JArray("moduleMvid", "token"),
						["additionalProperties"] = false,
					},
					"decompileEvent"),
				new ToolDef(
					"dnspy.getFieldInfo",
					"Get field metadata (type, flags, constant). See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
							["token"] = new JObject {
								["type"] = "integer",
								["description"] = "Field MD token (uint)",
							},
						},
						["required"] = new JArray("moduleMvid", "token"),
						["additionalProperties"] = false,
					},
					"getFieldInfo"),
				new ToolDef(
					"dnspy.getEnumInfo",
					"Get enum metadata and values. See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
							["typeToken"] = new JObject {
								["type"] = "integer",
								["description"] = "Enum type MD token (uint)",
							},
						},
						["required"] = new JArray("moduleMvid", "typeToken"),
						["additionalProperties"] = false,
					},
					"getEnumInfo"),
				new ToolDef(
					"dnspy.getStructInfo",
					"Get struct metadata (layout, fields). See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
							["typeToken"] = new JObject {
								["type"] = "integer",
								["description"] = "Struct type MD token (uint)",
							},
						},
						["required"] = new JArray("moduleMvid", "typeToken"),
						["additionalProperties"] = false,
					},
					"getStructInfo"),
				new ToolDef(
					"dnspy.getInterfaceInfo",
					"Get interface metadata (members, base interfaces). See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["moduleMvid"] = new JObject {
								["type"] = "string",
								["description"] = "Module MVID GUID",
							},
							["typeToken"] = new JObject {
								["type"] = "integer",
								["description"] = "Interface type MD token (uint)",
							},
						},
						["required"] = new JArray("moduleMvid", "typeToken"),
						["additionalProperties"] = false,
					},
					"getInterfaceInfo"),
				new ToolDef(
					"dnspy.search",
					"Search using dnSpyEx search settings (text, type, location, filters). See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject {
							["searchText"] = new JObject {
								["type"] = "string",
								["description"] = "Search text",
							},
							["searchType"] = new JObject {
								["type"] = "string",
								["description"] = "assembly|module|namespace|type|field|method|property|event|param|local|paramLocal|assemblyRef|moduleRef|resource|generic|nonGeneric|enum|interface|class|struct|delegate|member|any|literal",
							},
							["searchLocation"] = new JObject {
								["type"] = "string",
								["description"] = "allFiles|selectedFiles|allFilesInSameDir|selectedType",
							},
							["caseSensitive"] = new JObject { ["type"] = "boolean" },
							["matchWholeWords"] = new JObject { ["type"] = "boolean" },
							["matchAnySearchTerm"] = new JObject { ["type"] = "boolean" },
							["searchDecompiledData"] = new JObject { ["type"] = "boolean" },
							["searchFrameworkAssemblies"] = new JObject { ["type"] = "boolean" },
							["searchCompilerGeneratedMembers"] = new JObject { ["type"] = "boolean" },
							["syntaxHighlight"] = new JObject { ["type"] = "boolean" },
							["maxResults"] = new JObject { ["type"] = "integer" },
						},
						["required"] = new JArray("searchText"),
						["additionalProperties"] = false,
					},
					"search"),
				new ToolDef(
					"dnspy.getSelectedText",
					"Get the current selection text from the active document tab. See dnspy.exampleFlow for examples.",
					new JObject {
						["type"] = "object",
						["properties"] = new JObject(),
						["additionalProperties"] = false,
					},
					"getSelectedText"),
			};

			var map = new Dictionary<string, ToolDef>();
			foreach (var tool in list)
				map[tool.Name] = tool;
			Tools = map;
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
