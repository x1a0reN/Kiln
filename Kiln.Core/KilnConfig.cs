using System;
using System.IO;
using System.Text.Json;

namespace Kiln.Core {
	public sealed class KilnConfig {
		public string? IdaPath { get; set; }
		public string? Il2CppDumperPath { get; set; }
		public string WorkspaceRoot { get; set; } = string.Empty;

		public static KilnConfig Load(string? baseDirectory = null) {
			var root = string.IsNullOrWhiteSpace(baseDirectory)
				? Directory.GetCurrentDirectory()
				: baseDirectory;

			var defaults = new KilnConfig {
				WorkspaceRoot = Path.Combine(root, "workspace"),
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
				if (string.IsNullOrWhiteSpace(loaded.WorkspaceRoot))
					loaded.WorkspaceRoot = defaults.WorkspaceRoot;
				return loaded;
			}
			catch {
				return defaults;
			}
		}
	}
}
