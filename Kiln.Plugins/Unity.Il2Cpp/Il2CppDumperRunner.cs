using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace Kiln.Plugins.Unity.Il2Cpp {
	public static class Il2CppDumperRunner {
		public static Il2CppDumpResult Run(string gameAssemblyPath, string metadataPath, string dumperPath, string outputDir) {
			if (string.IsNullOrWhiteSpace(gameAssemblyPath) || !File.Exists(gameAssemblyPath))
				throw new FileNotFoundException("GameAssembly.dll not found.", gameAssemblyPath);
			if (string.IsNullOrWhiteSpace(metadataPath) || !File.Exists(metadataPath))
				throw new FileNotFoundException("global-metadata.dat not found.", metadataPath);
			if (string.IsNullOrWhiteSpace(dumperPath))
				throw new ArgumentException("dumperPath is required", nameof(dumperPath));

			var dumperExe = ResolveDumperExecutable(dumperPath);
			if (dumperExe is null)
				throw new FileNotFoundException("Il2CppDumper.exe not found.", dumperPath);

			Directory.CreateDirectory(outputDir);

			var psi = new ProcessStartInfo {
				FileName = dumperExe,
				Arguments = $"\"{gameAssemblyPath}\" \"{metadataPath}\" \"{outputDir}\"",
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true,
			};

			using var process = Process.Start(psi);
			if (process is null)
				throw new InvalidOperationException("Failed to start Il2CppDumper process.");

			var stdoutTask = process.StandardOutput.ReadToEndAsync();
			var stderrTask = process.StandardError.ReadToEndAsync();
			process.WaitForExit();
			Task.WaitAll(stdoutTask, stderrTask);
			var stdout = stdoutTask.Result;
			var stderr = stderrTask.Result;

			return new Il2CppDumpResult(
				process.ExitCode == 0,
				process.ExitCode,
				gameAssemblyPath,
				metadataPath,
				outputDir,
				stdout,
				stderr
			);
		}

		static string? ResolveDumperExecutable(string dumperPath) {
			if (File.Exists(dumperPath))
				return IsIl2CppDumperExecutable(dumperPath) ? dumperPath : null;

			if (!Directory.Exists(dumperPath))
				return null;

			var exe = Directory.EnumerateFiles(dumperPath, "Il2CppDumper.exe", SearchOption.TopDirectoryOnly)
				.FirstOrDefault();

			return exe;
		}

		static bool IsIl2CppDumperExecutable(string path) {
			var fileName = Path.GetFileName(path);
			return string.Equals(fileName, "Il2CppDumper.exe", StringComparison.OrdinalIgnoreCase);
		}
	}
}
