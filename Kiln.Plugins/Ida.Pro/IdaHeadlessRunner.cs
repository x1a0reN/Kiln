using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Kiln.Plugins.Ida.Pro {
	public static class IdaHeadlessRunner {
		public static async Task<IdaAnalyzeResult> RunAsync(
			string idaPath,
			string inputBinaryPath,
			string outputDir,
			string? scriptPath,
			IReadOnlyList<string>? scriptArgs,
			CancellationToken token,
			Action<string>? log = null) {
			if (string.IsNullOrWhiteSpace(idaPath) || !File.Exists(idaPath))
				throw new FileNotFoundException("idat64.exe not found.", idaPath);
			if (string.IsNullOrWhiteSpace(inputBinaryPath) || !File.Exists(inputBinaryPath))
				throw new FileNotFoundException("Input binary not found.", inputBinaryPath);
			if (!string.IsNullOrWhiteSpace(scriptPath) && !File.Exists(scriptPath))
				throw new FileNotFoundException("IDA script not found.", scriptPath);

			Directory.CreateDirectory(outputDir);

			var isDatabase = IsDatabaseFile(inputBinaryPath);
			var dbPath = isDatabase ? inputBinaryPath : GetDatabasePath(idaPath, inputBinaryPath, outputDir);
			var logPath = Path.Combine(outputDir, "ida.log");

			var args = new List<string> {
				"-A",
				$"-L\"{logPath}\"",
			};
			if (!isDatabase)
				args.Add($"-o\"{dbPath}\"");

			if (!string.IsNullOrWhiteSpace(scriptPath)) {
				args.Add($"-S{scriptPath}");
				if (scriptArgs is not null) {
					foreach (var arg in scriptArgs)
						args.Add(arg);
				}
			}

			args.Add($"\"{inputBinaryPath}\"");

			var psi = new ProcessStartInfo {
				FileName = idaPath,
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true,
			};
			foreach (var arg in args)
				psi.ArgumentList.Add(arg);

			using var process = new Process { StartInfo = psi };
			if (!process.Start())
				throw new InvalidOperationException("Failed to start IDA process.");

			using var _ = token.Register(() => {
				try {
					if (!process.HasExited)
						process.Kill(true);
				}
				catch {
				}
			});

			log?.Invoke($"IDA started: {psi.FileName} {psi.Arguments}");

			var stdoutTask = process.StandardOutput.ReadToEndAsync();
			var stderrTask = process.StandardError.ReadToEndAsync();

			try {
				await process.WaitForExitAsync(token).ConfigureAwait(false);
			}
			catch (OperationCanceledException) {
				throw;
			}

			await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);

			var stdout = stdoutTask.Result;
			var stderr = stderrTask.Result;
			if (!string.IsNullOrWhiteSpace(stdout))
				log?.Invoke(stdout.Trim());
			if (!string.IsNullOrWhiteSpace(stderr))
				log?.Invoke(stderr.Trim());

			return new IdaAnalyzeResult(
				process.ExitCode == 0,
				process.ExitCode,
				inputBinaryPath,
				dbPath,
				logPath,
				stdout,
				stderr
			);
		}

		public static string GetAutoLoadScriptPath() {
			return ResolveScriptPath("IdaAutoLoadSymbols.py");
		}

		public static string GetExportSymbolsScriptPath() {
			return ResolveScriptPath("ida_export_symbols.py");
		}

		public static string GetExportPseudocodeScriptPath() {
			return ResolveScriptPath("ida_export_pseudocode.py");
		}

		public static string GetDatabasePath(string idaPath, string inputBinaryPath, string outputDir) {
			var is64 = Is64BitIda(idaPath);
			var dbExt = is64 ? ".i64" : ".idb";
			return Path.Combine(outputDir, Path.GetFileNameWithoutExtension(inputBinaryPath) + dbExt);
		}

		static bool Is64BitIda(string idaPath) {
			var name = Path.GetFileName(idaPath);
			if (string.IsNullOrWhiteSpace(name))
				return false;
			if (name.Contains("64", StringComparison.OrdinalIgnoreCase))
				return true;
			if (string.Equals(name, "idat.exe", StringComparison.OrdinalIgnoreCase))
				return true;
			if (string.Equals(name, "ida.exe", StringComparison.OrdinalIgnoreCase))
				return true;
			return false;
		}

		static bool IsDatabaseFile(string path) {
			var ext = Path.GetExtension(path);
			return ext.Equals(".i64", StringComparison.OrdinalIgnoreCase)
				|| ext.Equals(".idb", StringComparison.OrdinalIgnoreCase);
		}

		static string ResolveScriptPath(string fileName) {
			var baseDir = Path.GetDirectoryName(typeof(IdaHeadlessRunner).Assembly.Location);
			var appDir = AppContext.BaseDirectory;
			var candidates = new List<string>();

			if (!string.IsNullOrWhiteSpace(baseDir))
				candidates.Add(Path.Combine(baseDir, fileName));
			if (!string.IsNullOrWhiteSpace(appDir))
				candidates.Add(Path.Combine(appDir, fileName));
			if (!string.IsNullOrWhiteSpace(baseDir)) {
				try {
					var parent = Directory.GetParent(baseDir);
					if (parent is not null)
						candidates.Add(Path.Combine(parent.FullName, fileName));
				}
				catch {
				}
			}

			foreach (var candidate in candidates) {
				if (File.Exists(candidate))
					return candidate;
			}

			if (!string.IsNullOrWhiteSpace(appDir))
				return Path.Combine(appDir, fileName);
			if (!string.IsNullOrWhiteSpace(baseDir))
				return Path.Combine(baseDir, fileName);
			return fileName;
		}

		// Script args are passed as separate CLI args to IDA (after -S<script>).
	}
}
