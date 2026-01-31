using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Kiln.Plugins.Packaging {
	public static class PatchCodegenRunner {
		const int MaxTargets = 50;
		const int MaxReasons = 8;
		const int MaxStringsPerTarget = 6;
		const int MaxStringsPerFunction = 20;
		const int MaxCallsSample = 12;

		public static PatchCodegenResult Run(string requirements, IReadOnlyList<string> analysisArtifacts, string outputDir) {
			if (string.IsNullOrWhiteSpace(requirements))
				throw new ArgumentException("requirements is required", nameof(requirements));
			if (string.IsNullOrWhiteSpace(outputDir))
				throw new ArgumentException("outputDir is required", nameof(outputDir));

			Directory.CreateDirectory(outputDir);
			var srcDir = Path.Combine(outputDir, "src");
			Directory.CreateDirectory(srcDir);

			var analysis = AnalyzeArtifacts(requirements, analysisArtifacts);
			var jsonOptions = new JsonSerializerOptions {
				WriteIndented = true,
				PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
			};

			var files = new List<string>();
			var readmePath = Path.Combine(outputDir, "README.md");
			File.WriteAllText(readmePath, BuildReadme(requirements, analysisArtifacts, analysis));
			files.Add(readmePath);

			var artifactsPath = Path.Combine(outputDir, "analysis_artifacts.json");
			File.WriteAllText(artifactsPath, JsonSerializer.Serialize(analysisArtifacts, jsonOptions));
			files.Add(artifactsPath);

			var summaryPath = Path.Combine(outputDir, "analysis_summary.json");
			File.WriteAllText(summaryPath, JsonSerializer.Serialize(analysis.Summary, jsonOptions));
			files.Add(summaryPath);

			var targetsPath = Path.Combine(outputDir, "patch_targets.json");
			File.WriteAllText(targetsPath, JsonSerializer.Serialize(analysis.Targets, jsonOptions));
			files.Add(targetsPath);

			var targetsSourcePath = Path.Combine(srcDir, "PatchTargets.cs");
			File.WriteAllText(targetsSourcePath, BuildPatchTargetsSource(analysis.Targets));
			files.Add(targetsSourcePath);

			var pluginPath = Path.Combine(srcDir, "Plugin.cs");
			File.WriteAllText(pluginPath, PluginTemplate);
			files.Add(pluginPath);

			return new PatchCodegenResult(outputDir, files);
		}

		static PatchAnalysis AnalyzeArtifacts(string requirements, IReadOnlyList<string> artifacts) {
			var keywords = ExtractKeywords(requirements);
			var resolved = ResolveArtifacts(artifacts);
			var symbols = string.IsNullOrWhiteSpace(resolved.SymbolsPath)
				? new List<SymbolInfo>()
				: LoadSymbols(resolved.SymbolsPath);
			var strings = string.IsNullOrWhiteSpace(resolved.StringsPath)
				? new List<StringInfo>()
				: LoadStrings(resolved.StringsPath);
			var pseudocode = string.IsNullOrWhiteSpace(resolved.PseudocodePath)
				? new List<PseudocodeInfo>()
				: LoadPseudocode(resolved.PseudocodePath);

			var stringHits = BuildStringHits(strings, keywords);
			var pseudocodeHits = BuildPseudocodeHits(pseudocode, keywords);
			var targets = BuildTargets(symbols, stringHits, pseudocodeHits, keywords);

			var counts = new AnalysisCounts {
				Symbols = string.IsNullOrWhiteSpace(resolved.SymbolsPath) ? null : symbols.Count,
				Strings = string.IsNullOrWhiteSpace(resolved.StringsPath) ? null : strings.Count,
				Pseudocode = ReadCount(resolved.PseudocodePath, "functions"),
			};

			var summary = new AnalysisSummary {
				Requirements = requirements.Trim(),
				Keywords = keywords,
				GeneratedUtc = DateTime.UtcNow,
				Artifacts = new AnalysisArtifacts {
					Symbols = resolved.SymbolsPath,
					Strings = resolved.StringsPath,
					Pseudocode = resolved.PseudocodePath,
				},
				Counts = counts,
				TargetCount = targets.Count,
			};

			return new PatchAnalysis(summary, targets);
		}

		static ResolvedArtifacts ResolveArtifacts(IReadOnlyList<string> artifacts) {
			var resolved = new ResolvedArtifacts();
			foreach (var item in artifacts) {
				if (string.IsNullOrWhiteSpace(item))
					continue;
				var path = NormalizePath(item);
				if (!File.Exists(path))
					continue;

				if (IsMatch(path, "symbols.index.json"))
					resolved.SymbolsPath = path;
				else if (IsMatch(path, "symbols.json") && string.IsNullOrWhiteSpace(resolved.SymbolsPath))
					resolved.SymbolsPath = path;

				if (IsMatch(path, "strings.index.json"))
					resolved.StringsPath = path;
				else if (IsMatch(path, "strings.json") && string.IsNullOrWhiteSpace(resolved.StringsPath))
					resolved.StringsPath = path;

				if (IsMatch(path, "pseudocode.index.json"))
					resolved.PseudocodePath = path;
				else if (IsMatch(path, "pseudocode.json") && string.IsNullOrWhiteSpace(resolved.PseudocodePath))
					resolved.PseudocodePath = path;
			}

			if (!string.IsNullOrWhiteSpace(resolved.SymbolsPath)) {
				var dir = Path.GetDirectoryName(resolved.SymbolsPath);
				if (!string.IsNullOrWhiteSpace(dir)) {
					if (string.IsNullOrWhiteSpace(resolved.StringsPath)) {
						var stringsIndex = Path.Combine(dir, "strings.index.json");
						var stringsJson = Path.Combine(dir, "strings.json");
						if (File.Exists(stringsIndex))
							resolved.StringsPath = stringsIndex;
						else if (File.Exists(stringsJson))
							resolved.StringsPath = stringsJson;
					}
					if (string.IsNullOrWhiteSpace(resolved.PseudocodePath)) {
						var pseudoIndex = Path.Combine(dir, "pseudocode.index.json");
						var pseudoJson = Path.Combine(dir, "pseudocode.json");
						if (File.Exists(pseudoIndex))
							resolved.PseudocodePath = pseudoIndex;
						else if (File.Exists(pseudoJson))
							resolved.PseudocodePath = pseudoJson;
					}
				}
			}

			return resolved;
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

		static void FlushToken(StringBuilder buffer, List<string> list) {
			if (buffer.Length == 0)
				return;
			list.Add(buffer.ToString());
			buffer.Clear();
		}

		static Dictionary<string, List<string>> BuildStringHits(List<StringInfo> strings, List<string> keywords) {
			var hits = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
			if (keywords.Count == 0)
				return hits;

			foreach (var entry in strings) {
				if (string.IsNullOrWhiteSpace(entry.Value) || entry.Refs.Count == 0)
					continue;
				var valueLower = entry.ValueLower ?? entry.Value.ToLowerInvariant();
				if (!ContainsAny(valueLower, keywords))
					continue;

				foreach (var reference in entry.Refs) {
					var key = NormalizeEa(reference.FuncEa);
					if (string.IsNullOrWhiteSpace(key))
						continue;
					if (!hits.TryGetValue(key, out var list)) {
						list = new List<string>();
						hits[key] = list;
					}
					if (list.Count >= MaxStringsPerFunction)
						continue;
					list.Add(entry.Value);
				}
			}

			return hits;
		}

		static List<PatchTarget> BuildTargets(
			List<SymbolInfo> symbols,
			Dictionary<string, List<string>> stringHits,
			Dictionary<string, List<string>> pseudocodeHits,
			List<string> keywords) {
			var results = new List<PatchTarget>();
			foreach (var symbol in symbols) {
				var score = 0;
				var reasons = new List<string>();
				var nameLower = symbol.NameLower ?? symbol.Name.ToLowerInvariant();
				var sigLower = symbol.SignatureLower ?? symbol.Signature?.ToLowerInvariant();

				if (keywords.Count == 0) {
					score = 1;
					if (symbol.Size > 0)
						reasons.Add("size");
				}
				else {
					foreach (var keyword in keywords) {
						if (nameLower.Contains(keyword, StringComparison.Ordinal)) {
							score += 3;
							reasons.Add($"name:{keyword}");
						}
						if (!string.IsNullOrWhiteSpace(sigLower) && sigLower.Contains(keyword, StringComparison.Ordinal)) {
							score += 2;
							reasons.Add($"signature:{keyword}");
						}
					}
				}

				var strings = new List<string>();
				if (stringHits.TryGetValue(NormalizeEa(symbol.Ea), out var matchedStrings)) {
					foreach (var item in matchedStrings.Distinct(StringComparer.OrdinalIgnoreCase)) {
						strings.Add(item);
						if (strings.Count >= MaxStringsPerTarget)
							break;
					}
					if (strings.Count > 0) {
						score += strings.Count;
						reasons.Add("string");
					}
				}

				if (pseudocodeHits.TryGetValue(NormalizeEa(symbol.Ea), out var matchedPseudo)) {
					var used = 0;
					foreach (var keyword in matchedPseudo.Distinct(StringComparer.OrdinalIgnoreCase)) {
						reasons.Add($"pseudocode:{keyword}");
						score += 2;
						used++;
						if (used >= MaxReasons)
							break;
					}
				}

				if (keywords.Count > 0 && score == 0)
					continue;

				results.Add(new PatchTarget {
					Name = symbol.Name,
					Ea = symbol.Ea,
					EndEa = symbol.EndEa,
					Size = symbol.Size,
					Signature = symbol.Signature,
					Score = score,
					Reasons = reasons.Take(MaxReasons).ToList(),
					Strings = strings,
					Calls = symbol.Calls.Take(MaxCallsSample).ToList(),
					Callers = symbol.Callers.Take(MaxCallsSample).ToList(),
					CallsCount = symbol.Calls.Count,
					CallersCount = symbol.Callers.Count,
				});
			}

			return results
				.OrderByDescending(t => t.Score)
				.ThenByDescending(t => t.Size)
				.ThenBy(t => t.Name)
				.Take(MaxTargets)
				.ToList();
		}

		static List<SymbolInfo> LoadSymbols(string path) {
			var list = new List<SymbolInfo>();
			using var stream = File.OpenRead(path);
			using var doc = JsonDocument.Parse(stream);
			if (!doc.RootElement.TryGetProperty("symbols", out var symbols) || symbols.ValueKind != JsonValueKind.Array)
				return list;

			foreach (var item in symbols.EnumerateArray()) {
				var name = item.TryGetProperty("name", out var nameProp) ? nameProp.GetString() ?? string.Empty : string.Empty;
				if (string.IsNullOrWhiteSpace(name))
					continue;
				var ea = item.TryGetProperty("ea", out var eaProp) ? eaProp.GetString() ?? string.Empty : string.Empty;
				var endEa = item.TryGetProperty("endEa", out var endProp) ? endProp.GetString() : null;
				var size = item.TryGetProperty("size", out var sizeProp) && sizeProp.TryGetInt64(out var value) ? value : 0;
				var signature = item.TryGetProperty("signature", out var sigProp) ? sigProp.GetString() : null;
				var calls = ReadStringArray(item, "calls");
				var callers = ReadStringArray(item, "callers");

				list.Add(new SymbolInfo {
					Name = name,
					NameLower = item.TryGetProperty("nameLower", out var lower) ? (lower.GetString() ?? name.ToLowerInvariant()) : name.ToLowerInvariant(),
					Ea = ea,
					EndEa = endEa,
					Size = size,
					Signature = signature,
					SignatureLower = item.TryGetProperty("signatureLower", out var sigLower) ? sigLower.GetString() : signature?.ToLowerInvariant(),
					Calls = calls,
					Callers = callers,
				});
			}

			return list;
		}

		static List<StringInfo> LoadStrings(string path) {
			var list = new List<StringInfo>();
			using var stream = File.OpenRead(path);
			using var doc = JsonDocument.Parse(stream);
			if (!doc.RootElement.TryGetProperty("strings", out var strings) || strings.ValueKind != JsonValueKind.Array)
				return list;

			foreach (var item in strings.EnumerateArray()) {
				var value = item.TryGetProperty("value", out var valueProp) ? valueProp.GetString() ?? string.Empty : string.Empty;
				if (string.IsNullOrWhiteSpace(value))
					continue;
				var ea = item.TryGetProperty("ea", out var eaProp) ? eaProp.GetString() ?? string.Empty : string.Empty;
				var length = item.TryGetProperty("length", out var lenProp) && lenProp.TryGetInt32(out var len) ? len : value.Length;
				var refs = ReadStringRefs(item);
				list.Add(new StringInfo {
					Ea = ea,
					Value = value,
					ValueLower = item.TryGetProperty("valueLower", out var lower) ? lower.GetString() : value.ToLowerInvariant(),
					Length = length,
					Refs = refs,
				});
			}

			return list;
		}

		static List<PseudocodeInfo> LoadPseudocode(string path) {
			var list = new List<PseudocodeInfo>();
			using var stream = File.OpenRead(path);
			using var doc = JsonDocument.Parse(stream);
			if (!doc.RootElement.TryGetProperty("functions", out var funcs) || funcs.ValueKind != JsonValueKind.Array)
				return list;

			foreach (var item in funcs.EnumerateArray()) {
				var name = item.TryGetProperty("name", out var nameProp) ? nameProp.GetString() ?? string.Empty : string.Empty;
				var ea = item.TryGetProperty("ea", out var eaProp) ? eaProp.GetString() ?? string.Empty : string.Empty;
				var code = item.TryGetProperty("pseudocode", out var codeProp) ? codeProp.GetString() ?? string.Empty : string.Empty;
				if (string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(ea))
					continue;
				list.Add(new PseudocodeInfo {
					Name = name,
					Ea = ea,
					Pseudocode = code,
					PseudocodeLower = string.IsNullOrWhiteSpace(code) ? string.Empty : code.ToLowerInvariant(),
				});
			}

			return list;
		}

		static Dictionary<string, List<string>> BuildPseudocodeHits(List<PseudocodeInfo> pseudocode, List<string> keywords) {
			var hits = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
			if (keywords.Count == 0)
				return hits;

			foreach (var entry in pseudocode) {
				if (string.IsNullOrWhiteSpace(entry.Pseudocode))
					continue;
				if (!ContainsAny(entry.PseudocodeLower ?? entry.Pseudocode.ToLowerInvariant(), keywords))
					continue;

				var key = NormalizeEa(entry.Ea);
				if (string.IsNullOrWhiteSpace(key))
					continue;
				if (!hits.TryGetValue(key, out var list)) {
					list = new List<string>();
					hits[key] = list;
				}
				foreach (var keyword in keywords) {
					if (entry.PseudocodeLower?.Contains(keyword, StringComparison.OrdinalIgnoreCase) == true) {
						list.Add(keyword);
						if (list.Count >= MaxReasons)
							break;
					}
				}
			}

			return hits;
		}

		static int? ReadCount(string? path, string arrayName) {
			if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
				return null;
			try {
				using var stream = File.OpenRead(path);
				using var doc = JsonDocument.Parse(stream);
				if (doc.RootElement.TryGetProperty("count", out var countProp) && countProp.TryGetInt32(out var count))
					return count;
				if (doc.RootElement.TryGetProperty(arrayName, out var arr) && arr.ValueKind == JsonValueKind.Array)
					return arr.GetArrayLength();
			}
			catch {
			}
			return null;
		}

		static List<string> ReadStringArray(JsonElement item, string name) {
			var list = new List<string>();
			if (!item.TryGetProperty(name, out var array) || array.ValueKind != JsonValueKind.Array)
				return list;
			foreach (var value in array.EnumerateArray()) {
				if (value.ValueKind == JsonValueKind.String) {
					var text = value.GetString();
					if (!string.IsNullOrWhiteSpace(text))
						list.Add(text);
				}
			}
			return list;
		}

		static List<StringRef> ReadStringRefs(JsonElement item) {
			var list = new List<StringRef>();
			if (!item.TryGetProperty("refs", out var refs) || refs.ValueKind != JsonValueKind.Array)
				return list;
			foreach (var entry in refs.EnumerateArray()) {
				var funcEa = entry.TryGetProperty("funcEa", out var eaProp) ? eaProp.GetString() ?? string.Empty : string.Empty;
				if (string.IsNullOrWhiteSpace(funcEa))
					continue;
				list.Add(new StringRef {
					FuncEa = funcEa,
					FuncName = entry.TryGetProperty("funcName", out var nameProp) ? nameProp.GetString() : null,
					RefEa = entry.TryGetProperty("refEa", out var refProp) ? refProp.GetString() : null,
				});
			}
			return list;
		}

		static bool ContainsAny(string value, IReadOnlyList<string> keywords) {
			for (var i = 0; i < keywords.Count; i++) {
				if (value.Contains(keywords[i], StringComparison.Ordinal))
					return true;
			}
			return false;
		}

		static string NormalizePath(string path) {
			try {
				return Path.GetFullPath(path);
			}
			catch {
				return path;
			}
		}

		static bool IsMatch(string path, string suffix) =>
			path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase);

		static string NormalizeEa(string? value) {
			if (string.IsNullOrWhiteSpace(value))
				return string.Empty;
			var text = value.Trim();
			if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
				text = text[2..];
			if (ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var hex))
				return $"0x{hex:x}";
			if (ulong.TryParse(text, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var dec))
				return $"0x{dec:x}";
			return value.Trim().ToLowerInvariant();
		}

		static string BuildReadme(string requirements, IReadOnlyList<string> artifacts, PatchAnalysis analysis) {
			var writer = new StringWriter();
			writer.WriteLine("# Kiln Patch Template");
			writer.WriteLine();
			writer.WriteLine("## Requirements");
			writer.WriteLine(requirements.Trim());
			writer.WriteLine();
			writer.WriteLine("## Analysis Artifacts");
			if (artifacts.Count == 0) {
				writer.WriteLine("- (none)");
			}
			else {
				foreach (var item in artifacts)
					writer.WriteLine($"- {item}");
			}
			writer.WriteLine();
			writer.WriteLine("## Analysis Summary");
			writer.WriteLine($"- Targets: {analysis.Targets.Count}");
			if (analysis.Summary.Keywords.Count > 0)
				writer.WriteLine($"- Keywords: {string.Join(", ", analysis.Summary.Keywords)}");
			else
				writer.WriteLine("- Keywords: (none)");
			writer.WriteLine();
			writer.WriteLine("Generated files:");
			writer.WriteLine("- analysis_summary.json");
			writer.WriteLine("- patch_targets.json");
			writer.WriteLine("- src/PatchTargets.cs");
			writer.WriteLine();
			writer.WriteLine("## Next Steps");
			writer.WriteLine("- Review patch_targets.json to pick candidate hooks.");
			writer.WriteLine("- Implement hook logic in src/Plugin.cs (Harmony for managed, native detour for addresses).");
			writer.WriteLine("- Build and package with package_mod");
			return writer.ToString();
		}

		static string BuildPatchTargetsSource(IReadOnlyList<PatchTarget> targets) {
			var builder = new StringBuilder();
			builder.AppendLine("using System;");
			builder.AppendLine();
			builder.AppendLine("namespace Kiln.Patches {");
			builder.AppendLine("\tpublic sealed class PatchTarget {");
			builder.AppendLine("\t\tpublic string Name { get; }");
			builder.AppendLine("\t\tpublic string Ea { get; }");
			builder.AppendLine("\t\tpublic string? EndEa { get; }");
			builder.AppendLine("\t\tpublic long Size { get; }");
			builder.AppendLine("\t\tpublic string? Signature { get; }");
			builder.AppendLine("\t\tpublic int Score { get; }");
			builder.AppendLine("\t\tpublic string[] Reasons { get; }");
			builder.AppendLine("\t\tpublic string[] Strings { get; }");
			builder.AppendLine("\t\tpublic string[] Calls { get; }");
			builder.AppendLine("\t\tpublic string[] Callers { get; }");
			builder.AppendLine();
			builder.AppendLine("\t\tpublic PatchTarget(string name, string ea, string? endEa, long size, string? signature, int score, string[] reasons, string[] strings, string[] calls, string[] callers) {");
			builder.AppendLine("\t\t\tName = name;");
			builder.AppendLine("\t\t\tEa = ea;");
			builder.AppendLine("\t\t\tEndEa = endEa;");
			builder.AppendLine("\t\t\tSize = size;");
			builder.AppendLine("\t\t\tSignature = signature;");
			builder.AppendLine("\t\t\tScore = score;");
			builder.AppendLine("\t\t\tReasons = reasons;");
			builder.AppendLine("\t\t\tStrings = strings;");
			builder.AppendLine("\t\t\tCalls = calls;");
			builder.AppendLine("\t\t\tCallers = callers;");
			builder.AppendLine("\t\t}");
			builder.AppendLine("\t}");
			builder.AppendLine();
			builder.AppendLine("\tpublic static class PatchTargets {");
			builder.AppendLine("\t\tpublic static readonly PatchTarget[] Targets = new PatchTarget[] {");

			foreach (var target in targets) {
				builder.Append("\t\t\tnew PatchTarget(");
				builder.Append(EscapeCSharp(target.Name));
				builder.Append(", ");
				builder.Append(EscapeCSharp(target.Ea));
				builder.Append(", ");
				builder.Append(target.EndEa is null ? "null" : EscapeCSharp(target.EndEa));
				builder.Append(", ");
				builder.Append(target.Size.ToString(System.Globalization.CultureInfo.InvariantCulture));
				builder.Append(", ");
				builder.Append(target.Signature is null ? "null" : EscapeCSharp(target.Signature));
				builder.Append(", ");
				builder.Append(target.Score.ToString(System.Globalization.CultureInfo.InvariantCulture));
				builder.Append(", ");
				builder.Append(FormatStringArray(target.Reasons));
				builder.Append(", ");
				builder.Append(FormatStringArray(target.Strings));
				builder.Append(", ");
				builder.Append(FormatStringArray(target.Calls));
				builder.Append(", ");
				builder.Append(FormatStringArray(target.Callers));
				builder.AppendLine("),");
			}

			builder.AppendLine("\t\t};");
			builder.AppendLine("\t}");
			builder.AppendLine("}");
			return builder.ToString();
		}

		static string EscapeCSharp(string value) {
			var builder = new StringBuilder(value.Length + 8);
			foreach (var ch in value) {
				switch (ch) {
					case '\\':
						builder.Append("\\\\");
						break;
					case '"':
						builder.Append("\\\"");
						break;
					case '\0':
						builder.Append("\\0");
						break;
					case '\a':
						builder.Append("\\a");
						break;
					case '\b':
						builder.Append("\\b");
						break;
					case '\f':
						builder.Append("\\f");
						break;
					case '\n':
						builder.Append("\\n");
						break;
					case '\r':
						builder.Append("\\r");
						break;
					case '\t':
						builder.Append("\\t");
						break;
					case '\v':
						builder.Append("\\v");
						break;
					default:
						if (char.IsControl(ch)) {
							builder.Append("\\u");
							builder.Append(((int)ch).ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
						}
						else {
							builder.Append(ch);
						}
						break;
				}
			}
			return $"\"{builder}\"";
		}

		static string FormatStringArray(IReadOnlyList<string> values) {
			if (values.Count == 0)
				return "Array.Empty<string>()";
			var parts = values.Select(EscapeCSharp);
			return $"new [] {{ {string.Join(", ", parts)} }}";
		}

		const string PluginTemplate =
@"using System;
using System.Linq;
using System.Reflection;
using BepInEx;
using BepInEx.Unity.IL2CPP;
using BepInEx.Logging;
using HarmonyLib;

namespace Kiln.Patches {
	[BepInPlugin(""com.kiln.patch"", ""KilnPatch"", ""0.1.0"")]
	public sealed class Plugin : BasePlugin {
		public static ManualLogSource LoggerInstance = null!;
		static readonly string[] DamageKeywords = { ""damage"", ""hurt"", ""health"", ""hp"" };
		Harmony? _harmony;

		public override void Load() {
			LoggerInstance = Log;
			_harmony = new Harmony(""com.kiln.patch""); // HarmonyX (BepInEx IL2CPP)
			Log.LogInfo($""Kiln patch loaded. Targets: {PatchTargets.Targets.Length}."");

			var candidates = PatchTargets.Targets
				.Where(t => MatchKeywords(t, DamageKeywords))
				.OrderByDescending(t => t.Score)
				.Take(8)
				.ToArray();

			if (candidates.Length == 0) {
				Log.LogWarning(""No damage-related targets found; review patch_targets.json."");
				return;
			}

			foreach (var target in candidates) {
				var method = ResolveMethod(target.Name);
				if (method is null) {
					Log.LogWarning($""Resolve failed: {target.Name} ({target.Ea})"");
					continue;
				}

				_harmony.Patch(method, prefix: new HarmonyMethod(typeof(Patches), nameof(Patches.BlockDamagePrefix)));
				Log.LogInfo($""Patched: {target.Name} ({target.Ea})"");
			}
		}

		static bool MatchKeywords(PatchTarget target, string[] keywords) {
			foreach (var keyword in keywords) {
				if (Contains(target.Name, keyword) || Contains(target.Signature, keyword))
					return true;
				foreach (var reason in target.Reasons) {
					if (Contains(reason, keyword))
						return true;
				}
				foreach (var str in target.Strings) {
					if (Contains(str, keyword))
						return true;
				}
			}
			return false;
		}

		static bool Contains(string? value, string keyword) =>
			!string.IsNullOrWhiteSpace(value) && value.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0;

		static MethodBase? ResolveMethod(string name) {
			if (string.IsNullOrWhiteSpace(name))
				return null;

			var parts = name.Split(new[] { ""$$"" }, 2, StringSplitOptions.None);
			if (parts.Length == 2) {
				var typeName = parts[0];
				var methodName = parts[1];
				var type = FindType(typeName);
				if (type is not null)
					return AccessTools.Method(type, methodName);
			}

			// Fallback: try Harmony's string-based resolver.
			return AccessTools.Method(name);
		}

		static Type? FindType(string typeName) {
			foreach (var asm in AppDomain.CurrentDomain.GetAssemblies()) {
				Type? type = null;
				try {
					type = asm.GetTypes().FirstOrDefault(t =>
						string.Equals(t.Name, typeName, StringComparison.Ordinal) ||
						(t.FullName?.EndsWith(""."" + typeName, StringComparison.Ordinal) ?? false));
				}
				catch (ReflectionTypeLoadException ex) {
					type = ex.Types?.FirstOrDefault(t =>
						t is not null && (
							string.Equals(t.Name, typeName, StringComparison.Ordinal) ||
							(t.FullName?.EndsWith(""."" + typeName, StringComparison.Ordinal) ?? false)));
				}
				catch {
				}

				if (type is not null)
					return type;
			}

			return null;
		}
	}

	static class Patches {
		public static bool BlockDamagePrefix() {
			Plugin.LoggerInstance.LogInfo(""BlockDamagePrefix hit."");
			return false; // skip original (invincible)
		}
	}
}";

		sealed record PatchAnalysis(AnalysisSummary Summary, IReadOnlyList<PatchTarget> Targets);

		sealed class AnalysisSummary {
			public string Requirements { get; set; } = string.Empty;
			public List<string> Keywords { get; set; } = new();
			public DateTime GeneratedUtc { get; set; }
			public AnalysisArtifacts Artifacts { get; set; } = new();
			public AnalysisCounts Counts { get; set; } = new();
			public int TargetCount { get; set; }
		}

		sealed class AnalysisArtifacts {
			public string? Symbols { get; set; }
			public string? Strings { get; set; }
			public string? Pseudocode { get; set; }
		}

		sealed class AnalysisCounts {
			public int? Symbols { get; set; }
			public int? Strings { get; set; }
			public int? Pseudocode { get; set; }
		}

		sealed class ResolvedArtifacts {
			public string? SymbolsPath { get; set; }
			public string? StringsPath { get; set; }
			public string? PseudocodePath { get; set; }
		}

		sealed class SymbolInfo {
			public string Name { get; set; } = string.Empty;
			public string NameLower { get; set; } = string.Empty;
			public string Ea { get; set; } = string.Empty;
			public string? EndEa { get; set; }
			public long Size { get; set; }
			public string? Signature { get; set; }
			public string? SignatureLower { get; set; }
			public List<string> Calls { get; set; } = new();
			public List<string> Callers { get; set; } = new();
		}

		sealed class StringInfo {
			public string Ea { get; set; } = string.Empty;
			public string Value { get; set; } = string.Empty;
			public string? ValueLower { get; set; }
			public int Length { get; set; }
			public List<StringRef> Refs { get; set; } = new();
		}

		sealed class StringRef {
			public string FuncEa { get; set; } = string.Empty;
			public string? FuncName { get; set; }
			public string? RefEa { get; set; }
		}

		sealed class PseudocodeInfo {
			public string Name { get; set; } = string.Empty;
			public string Ea { get; set; } = string.Empty;
			public string Pseudocode { get; set; } = string.Empty;
			public string? PseudocodeLower { get; set; }
		}

		sealed class PatchTarget {
			public string Name { get; set; } = string.Empty;
			public string Ea { get; set; } = string.Empty;
			public string? EndEa { get; set; }
			public long Size { get; set; }
			public string? Signature { get; set; }
			public int Score { get; set; }
			public List<string> Reasons { get; set; } = new();
			public List<string> Strings { get; set; } = new();
			public List<string> Calls { get; set; } = new();
			public List<string> Callers { get; set; } = new();
			public int CallsCount { get; set; }
			public int CallersCount { get; set; }
		}
	}
}
