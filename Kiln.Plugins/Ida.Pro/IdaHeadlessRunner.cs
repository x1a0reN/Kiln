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

			var is64 = string.Equals(Path.GetFileName(idaPath), "idat64.exe", StringComparison.OrdinalIgnoreCase);
			var dbExt = is64 ? ".i64" : ".idb";
			var dbPath = Path.Combine(outputDir, Path.GetFileNameWithoutExtension(inputBinaryPath) + dbExt);
			var logPath = Path.Combine(outputDir, "ida.log");

			var args = new List<string> {
				"-A",
				$"-L\"{logPath}\"",
				$"-o\"{dbPath}\"",
			};

			if (!string.IsNullOrWhiteSpace(scriptPath))
				args.Add($"-S{BuildScriptInvocation(scriptPath, scriptArgs)}");

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
			var baseDir = Path.GetDirectoryName(typeof(IdaHeadlessRunner).Assembly.Location);
			if (string.IsNullOrWhiteSpace(baseDir))
				baseDir = AppContext.BaseDirectory;
			return Path.Combine(baseDir, "IdaAutoLoadSymbols.py");
		}

		public static string GetExportSymbolsScriptPath() {
			var baseDir = Path.GetDirectoryName(typeof(IdaHeadlessRunner).Assembly.Location);
			if (string.IsNullOrWhiteSpace(baseDir))
				baseDir = AppContext.BaseDirectory;
			return Path.Combine(baseDir, "ida_export_symbols.py");
		}

		public static string GetExportPseudocodeScriptPath() {
			var baseDir = Path.GetDirectoryName(typeof(IdaHeadlessRunner).Assembly.Location);
			if (string.IsNullOrWhiteSpace(baseDir))
				baseDir = AppContext.BaseDirectory;
			return Path.Combine(baseDir, "ida_export_pseudocode.py");
		}

		static string BuildScriptInvocation(string scriptPath, IReadOnlyList<string>? scriptArgs) {
			var parts = new List<string> { QuoteForIda(scriptPath) };
			if (scriptArgs is not null) {
				foreach (var arg in scriptArgs)
					parts.Add(QuoteForIda(arg));
			}
			return string.Join(" ", parts);
		}

		static string QuoteForIda(string value) {
			var escaped = value.Replace("\"", "\\\"");
			return $"\"{escaped}\"";
		}
	}
}
