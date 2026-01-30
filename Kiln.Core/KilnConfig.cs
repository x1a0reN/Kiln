using System;
using System.IO;
using System.Text.Json;

namespace Kiln.Core {
	public sealed class KilnConfig {
		public string? IdaPath { get; set; }
		public string? IdaSymbolsScriptPath { get; set; }
		public string? Il2CppDumperPath { get; set; }
		public string Il2CppDumpDir { get; set; } = string.Empty;
		public string IdaOutputDir { get; set; } = string.Empty;
		public string WorkspaceRoot { get; set; } = string.Empty;

		public static KilnConfig Load(string? baseDirectory = null) {
			var root = ResolveRoot(baseDirectory);

			var defaults = new KilnConfig {
				Il2CppDumperPath = Path.Combine(root, "Il2CppDumper"),
				IdaSymbolsScriptPath = Path.Combine(root, "Il2CppDumper", "ida_with_struct_py3.py"),
				WorkspaceRoot = Path.Combine(root, "workspace"),
				Il2CppDumpDir = Path.Combine(root, "il2cpp_dump"),
				IdaOutputDir = Path.Combine(root, "ida"),
			};

			var configPath = Path.Combine(root, "kiln.config.json");
			if (!File.Exists(configPath))
				return defaults;

			try {
				var json = File.ReadAllText(configPath);
				var options = new JsonSerializerOptions {
					PropertyNameCaseInsensitive = true,
				};
				var loaded = JsonSerializer.Deserialize<KilnConfig>(json, options);
				if (loaded is null)
					return defaults;

				loaded.IdaPath = NormalizeOptionalPath(root, loaded.IdaPath);
				loaded.Il2CppDumperPath = NormalizePathWithDefault(root, loaded.Il2CppDumperPath, defaults.Il2CppDumperPath);
				loaded.IdaSymbolsScriptPath = NormalizePathWithDefault(root, loaded.IdaSymbolsScriptPath, defaults.IdaSymbolsScriptPath);
				loaded.Il2CppDumpDir = NormalizePathWithDefault(root, loaded.Il2CppDumpDir, defaults.Il2CppDumpDir);
				loaded.IdaOutputDir = NormalizePathWithDefault(root, loaded.IdaOutputDir, defaults.IdaOutputDir);
				loaded.WorkspaceRoot = NormalizePathWithDefault(root, loaded.WorkspaceRoot, defaults.WorkspaceRoot);
				return loaded;
			}
			catch {
				return defaults;
			}
		}

		static string ResolveRoot(string? baseDirectory) {
			if (!string.IsNullOrWhiteSpace(baseDirectory))
				return Path.GetFullPath(baseDirectory);

			var cwd = Directory.GetCurrentDirectory();
			if (File.Exists(Path.Combine(cwd, "kiln.config.json")))
				return Path.GetFullPath(cwd);

			var baseDir = AppContext.BaseDirectory;
			if (File.Exists(Path.Combine(baseDir, "kiln.config.json")))
				return Path.GetFullPath(baseDir);

			return Path.GetFullPath(baseDir);
		}

		static string? NormalizeOptionalPath(string root, string? value) {
			if (string.IsNullOrWhiteSpace(value))
				return value;
			var combined = Path.IsPathRooted(value) ? value : Path.Combine(root, value);
			return Path.GetFullPath(combined);
		}

		static string NormalizePathWithDefault(string root, string? value, string defaultValue) {
			var resolved = string.IsNullOrWhiteSpace(value) ? defaultValue : value;
			var combined = Path.IsPathRooted(resolved) ? resolved : Path.Combine(root, resolved);
			return Path.GetFullPath(combined);
		}
	}
}
