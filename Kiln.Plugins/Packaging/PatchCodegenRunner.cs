using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Kiln.Plugins.Packaging {
	public static class PatchCodegenRunner {
		public static PatchCodegenResult Run(string requirements, IReadOnlyList<string> analysisArtifacts, string outputDir) {
			if (string.IsNullOrWhiteSpace(requirements))
				throw new ArgumentException("requirements is required", nameof(requirements));
			if (string.IsNullOrWhiteSpace(outputDir))
				throw new ArgumentException("outputDir is required", nameof(outputDir));

			Directory.CreateDirectory(outputDir);
			var srcDir = Path.Combine(outputDir, "src");
			Directory.CreateDirectory(srcDir);

			var files = new List<string>();
			var readmePath = Path.Combine(outputDir, "README.md");
			File.WriteAllText(readmePath, BuildReadme(requirements, analysisArtifacts));
			files.Add(readmePath);

			var artifactsPath = Path.Combine(outputDir, "analysis_artifacts.json");
			File.WriteAllText(artifactsPath, JsonSerializer.Serialize(analysisArtifacts, new JsonSerializerOptions { WriteIndented = true }));
			files.Add(artifactsPath);

			var pluginPath = Path.Combine(srcDir, "Plugin.cs");
			File.WriteAllText(pluginPath, PluginTemplate);
			files.Add(pluginPath);

			return new PatchCodegenResult(outputDir, files);
		}

		static string BuildReadme(string requirements, IReadOnlyList<string> artifacts) {
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
			writer.WriteLine("## Next Steps");
			writer.WriteLine("- Implement your patch logic in src/Plugin.cs");
			writer.WriteLine("- Build and package with package_mod");
			return writer.ToString();
		}

		const string PluginTemplate =
@"using BepInEx;
using BepInEx.Unity.IL2CPP;
using BepInEx.Logging;

namespace Kiln.Patches {
	[BepInPlugin(""com.kiln.patch"", ""KilnPatch"", ""0.1.0"")]
	public sealed class Plugin : BasePlugin {
		public static ManualLogSource LoggerInstance = null!;

		public override void Load() {
			LoggerInstance = Log;
			Log.LogInfo(""Kiln patch loaded."");
		}
	}
}";
	}
}
