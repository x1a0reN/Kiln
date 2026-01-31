using System;
using System.IO;
using System.Text.Json;

namespace Kiln.Core {
	public sealed class KilnConfig {
		public string? IdaPath { get; set; }
		public string Il2CppRootDir { get; set; } = string.Empty;
		public string IdaOutputDir { get; set; } = string.Empty;
		public string WorkspaceRoot { get; set; } = string.Empty;
		public string ModsRoot { get; set; } = string.Empty;
		public string? IdaMcpCommand { get; set; }
		public string[]? IdaMcpArgs { get; set; }
		public string? IdaMcpWorkingDir { get; set; }
		public bool IdaMcpEnabled { get; set; }

		public static KilnConfig Load(string? baseDirectory = null) {
			var root = ResolveRoot(baseDirectory);

			var defaults = new KilnConfig {
				Il2CppRootDir = Path.Combine(root, "Tools", "Il2CppDumper"),
				WorkspaceRoot = Path.Combine(root, "workspace"),
				IdaOutputDir = Path.Combine(root, "ida"),
				ModsRoot = Path.Combine(root, "mods"),
				IdaMcpCommand = string.Empty,
				IdaMcpArgs = Array.Empty<string>(),
				IdaMcpWorkingDir = string.Empty,
				IdaMcpEnabled = false,
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
				loaded.IdaMcpCommand = NormalizeCommand(root, loaded.IdaMcpCommand);
				loaded.IdaMcpWorkingDir = NormalizeOptionalPath(root, loaded.IdaMcpWorkingDir);
				loaded.IdaMcpArgs ??= Array.Empty<string>();
				if (!loaded.IdaMcpEnabled && !string.IsNullOrWhiteSpace(loaded.IdaMcpCommand))
					loaded.IdaMcpEnabled = true;
				if (string.IsNullOrWhiteSpace(loaded.IdaMcpCommand))
					loaded.IdaMcpEnabled = false;
				loaded.Il2CppRootDir = NormalizePathWithDefault(root, ResolveIl2CppRootDir(root, loaded), defaults.Il2CppRootDir);
				loaded.IdaOutputDir = NormalizePathWithDefault(root, loaded.IdaOutputDir, defaults.IdaOutputDir);
				loaded.WorkspaceRoot = NormalizePathWithDefault(root, loaded.WorkspaceRoot, defaults.WorkspaceRoot);
				loaded.ModsRoot = NormalizePathWithDefault(root, loaded.ModsRoot, defaults.ModsRoot);
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

		static string? NormalizeCommand(string root, string? value) {
			if (string.IsNullOrWhiteSpace(value))
				return value;
			var trimmed = value.Trim();
			if (trimmed.IndexOf(Path.DirectorySeparatorChar) >= 0 || trimmed.IndexOf(Path.AltDirectorySeparatorChar) >= 0 || trimmed.Contains(":")) {
				var combined = Path.IsPathRooted(trimmed) ? trimmed : Path.Combine(root, trimmed);
				return Path.GetFullPath(combined);
			}
			return trimmed;
		}

		static string NormalizePathWithDefault(string root, string? value, string defaultValue) {
			var resolved = string.IsNullOrWhiteSpace(value) ? defaultValue : value;
			var combined = Path.IsPathRooted(resolved) ? resolved : Path.Combine(root, resolved);
			return Path.GetFullPath(combined);
		}

		static string? ResolveIl2CppRootDir(string root, KilnConfig loaded) {
			if (!string.IsNullOrWhiteSpace(loaded.Il2CppRootDir))
				return loaded.Il2CppRootDir;

			if (!string.IsNullOrWhiteSpace(loaded.Il2CppDumperPath)) {
				var candidate = loaded.Il2CppDumperPath!;
				if (!Path.IsPathRooted(candidate))
					candidate = Path.Combine(root, candidate);
				if (File.Exists(candidate))
					return Path.GetDirectoryName(candidate);
				if (Directory.Exists(candidate))
					return candidate;
			}

			if (!string.IsNullOrWhiteSpace(loaded.IdaSymbolsScriptPath)) {
				var candidate = loaded.IdaSymbolsScriptPath!;
				if (!Path.IsPathRooted(candidate))
					candidate = Path.Combine(root, candidate);
				if (File.Exists(candidate))
					return Path.GetDirectoryName(candidate);
			}

			return null;
		}

		public string GetIl2CppDumperPath() =>
			Path.Combine(Il2CppRootDir, "Il2CppDumper.exe");

		public string GetIdaSymbolsScriptPath() =>
			Path.Combine(Il2CppRootDir, "ida_with_struct_py3.py");

		public string GetIl2CppDumpDir(string gameDir) {
			var name = GetSafeGameName(gameDir);
			return Path.Combine(Il2CppRootDir, name);
		}

		public string GetIdaOutputDirForGame(string gameDir) {
			var name = GetSafeGameName(gameDir);
			return Path.Combine(IdaOutputDir, name);
		}

		public string GetModsRootForGame(string gameDir) {
			var name = GetSafeGameName(gameDir);
			return Path.Combine(ModsRoot, name);
		}

		static string GetSafeGameName(string gameDir) {
			var trimmed = (gameDir ?? string.Empty).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
			var name = string.IsNullOrWhiteSpace(trimmed) ? "game" : Path.GetFileName(trimmed);
			if (string.IsNullOrWhiteSpace(name))
				name = "game";

			foreach (var ch in Path.GetInvalidFileNameChars())
				name = name.Replace(ch, '_');

			return name;
		}

		// Legacy fields (back-compat for older configs)
		public string? IdaSymbolsScriptPath { get; set; }
		public string? Il2CppDumperPath { get; set; }
	}
}
