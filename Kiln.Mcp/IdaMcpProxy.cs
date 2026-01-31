using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Kiln.Core;
using Kiln.Plugins.Ida.Pro;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Kiln.Mcp {
	sealed class IdaMcpProxy : IDisposable {
		const string ToolPrefix = "ida.";
		static readonly TimeSpan InitTimeout = TimeSpan.FromSeconds(10);
		static readonly TimeSpan ToolListTimeout = TimeSpan.FromSeconds(10);
		static readonly TimeSpan ToolCallTimeout = TimeSpan.FromSeconds(60);
		static readonly TimeSpan ToolCacheTtl = TimeSpan.FromMinutes(5);

		readonly McpStdioClient client;
		readonly KilnConfig config;
		readonly object idaGate = new object();
		Process? idaProcess;
		string? idaAutoScriptPath;
		bool pluginInstallAttempted;
		readonly object cacheGate = new object();
		List<IdaMcpProxyTool> cachedTools = new List<IdaMcpProxyTool>();
		DateTime lastSyncUtc = DateTime.MinValue;

		public bool Enabled { get; }
		public string Prefix => ToolPrefix;

		IdaMcpProxy(KilnConfig config) {
			this.config = config ?? throw new ArgumentNullException(nameof(config));
			Enabled = config.IdaMcpEnabled && !string.IsNullOrWhiteSpace(config.IdaMcpCommand);
			var args = config.IdaMcpArgs ?? Array.Empty<string>();
			client = new McpStdioClient(config.IdaMcpCommand ?? string.Empty, args, config.IdaMcpWorkingDir);
		}

		public static IdaMcpProxy? TryCreate(KilnConfig config) {
			if (config is null)
				throw new ArgumentNullException(nameof(config));
			if (!config.IdaMcpEnabled || string.IsNullOrWhiteSpace(config.IdaMcpCommand))
				return null;
			return new IdaMcpProxy(config);
		}

		public bool IsProxyTool(string name) =>
			!string.IsNullOrWhiteSpace(name) && name.StartsWith(ToolPrefix, StringComparison.OrdinalIgnoreCase);

		public string GetRemoteName(string localName) =>
			localName.Substring(ToolPrefix.Length);

		public async Task<IReadOnlyList<IdaMcpProxyTool>> GetToolsAsync(CancellationToken token) {
			if (!Enabled)
				return Array.Empty<IdaMcpProxyTool>();

			lock (cacheGate) {
				if (cachedTools.Count > 0 && DateTime.UtcNow - lastSyncUtc <= ToolCacheTtl)
					return cachedTools.ToArray();
			}

			try {
				await client.EnsureInitializedAsync(token, InitTimeout).ConfigureAwait(false);
				var response = await client.SendRequestAsync("tools/list", new JObject(), token, ToolListTimeout).ConfigureAwait(false);
				var tools = ParseTools(response);
				lock (cacheGate) {
					cachedTools = tools.ToList();
					lastSyncUtc = DateTime.UtcNow;
					return cachedTools.ToArray();
				}
			}
			catch (Exception ex) {
				KilnLog.Warn($"ida-pro-mcp tools/list failed: {ex.Message}");
				lock (cacheGate) {
					return cachedTools.ToArray();
				}
			}
		}

		public async Task<JObject> CallToolAsync(string localName, JObject args, CancellationToken token) {
			if (!Enabled)
				return BuildErrorResult("ida-pro-mcp proxy is disabled (set kiln.config.json: idaMcpEnabled + idaMcpCommand).");

			if (!IsProxyTool(localName))
				return BuildErrorResult($"Invalid ida tool name: {localName}");

			var remoteName = GetRemoteName(localName);
			try {
				await client.EnsureInitializedAsync(token, InitTimeout).ConfigureAwait(false);
				var payload = new JObject {
					["name"] = remoteName,
					["arguments"] = args ?? new JObject(),
				};
				var response = await client.SendRequestAsync("tools/call", payload, token, ToolCallTimeout).ConfigureAwait(false);
				var result = response["result"] as JObject;
				if (result is not null)
					return result;
				var error = response["error"] as JObject;
				if (error is not null) {
					var message = error["message"]?.Value<string>() ?? "ida-pro-mcp tool call failed.";
					return BuildErrorResult(message);
				}
				return BuildErrorResult("ida-pro-mcp returned an empty response.");
			}
			catch (Exception ex) {
				return BuildErrorResult($"ida-pro-mcp tool call failed: {ex.Message}");
			}
		}

		public async Task<bool> TryAutoStartAsync(string? databasePath, CancellationToken token) {
			if (!Enabled || !config.IdaMcpAutoStart)
				return false;

			var idaPath = config.IdaPath;
			if (string.IsNullOrWhiteSpace(idaPath) || !File.Exists(idaPath)) {
				KilnLog.Warn("ida-pro-mcp auto-start skipped: idaPath not configured.");
				return false;
			}

			EnsurePluginInstalled();

			var dbPath = ResolveDatabasePath(databasePath);
			if (string.IsNullOrWhiteSpace(dbPath) || !File.Exists(dbPath)) {
				KilnLog.Warn("ida-pro-mcp auto-start skipped: databasePath not found.");
				return false;
			}

			lock (idaGate) {
				if (idaProcess is not null && !idaProcess.HasExited)
					return true;
				IdaHeadlessRunner.CleanupUnpackedDatabase(dbPath);
				KilnLog.Info("ida-pro-mcp auto-start: cleaned unpacked database artifacts.");
				StartIdaProcess(idaPath, dbPath);
			}

			var ready = await WaitForIdaReadyAsync(token).ConfigureAwait(false);
			if (!ready)
				KilnLog.Warn("ida-pro-mcp auto-start: IDA server not ready yet.");
			return ready;
		}

		void EnsurePluginInstalled() {
			if (pluginInstallAttempted)
				return;

			pluginInstallAttempted = true;
			try {
				var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
				var pluginDir = Path.Combine(appData, "Hex-Rays", "IDA Pro", "plugins");
				var loaderPath = Path.Combine(pluginDir, "ida_mcp.py");
				if (File.Exists(loaderPath))
					return;

				KilnLog.Info("ida-pro-mcp plugin not found, attempting auto-install.");
				var installArgs = new List<string> { "--install", "--transport", "stdio" };
				var psi = new ProcessStartInfo {
					FileName = config.IdaMcpCommand ?? "ida-pro-mcp",
					UseShellExecute = false,
					RedirectStandardOutput = true,
					RedirectStandardError = true,
					CreateNoWindow = true,
				};
				foreach (var arg in installArgs)
					psi.ArgumentList.Add(arg);

				using var process = new Process { StartInfo = psi };
				if (!process.Start())
					return;
				process.WaitForExit(15000);
			}
			catch (Exception ex) {
				KilnLog.Warn($"ida-pro-mcp plugin auto-install failed: {ex.Message}");
			}
		}

		string? ResolveDatabasePath(string? databasePath) {
			if (!string.IsNullOrWhiteSpace(databasePath))
				return databasePath;
			if (!string.IsNullOrWhiteSpace(config.IdaMcpDatabasePath))
				return config.IdaMcpDatabasePath;
			return null;
		}

		async Task<bool> WaitForIdaReadyAsync(CancellationToken token) {
			var waitSeconds = config.IdaMcpAutoStartWaitSeconds <= 0 ? 180 : config.IdaMcpAutoStartWaitSeconds;
			var deadline = DateTime.UtcNow.AddSeconds(waitSeconds);
			while (DateTime.UtcNow < deadline && !token.IsCancellationRequested) {
				try {
					await client.EnsureInitializedAsync(token, InitTimeout).ConfigureAwait(false);
					var response = await client.SendRequestAsync("tools/list", new JObject(), token, ToolListTimeout).ConfigureAwait(false);
					if (response["result"]?["tools"] is JArray)
						return true;
				}
				catch {
				}
				await Task.Delay(1000, token).ConfigureAwait(false);
			}
			return false;
		}

		void StartIdaProcess(string idaPath, string databasePath) {
			var launchPath = ResolveIdaLaunchPath(idaPath, config.IdaMcpHeadless);
			if (string.IsNullOrWhiteSpace(launchPath) || !File.Exists(launchPath))
				throw new InvalidOperationException($"IDA executable not found: {launchPath}");
			if (config.IdaMcpHeadless && IsGuiIda(launchPath))
				throw new InvalidOperationException("ida-pro-mcp auto-start requires idat.exe/idat64.exe when idaMcpHeadless=true.");
			var scriptPath = GetAutoScriptPath();
			WriteAutoScript(scriptPath);

			var args = new List<string> {
				"-S" + BuildScriptInvocation(scriptPath),
			};
			if (config.IdaMcpHeadless)
				args.Insert(0, "-A");
			var logPath = Path.Combine(
				string.IsNullOrWhiteSpace(config.WorkspaceRoot) ? AppContext.BaseDirectory : config.WorkspaceRoot,
				"ida_mcp_ida.log");
			args.Insert(0, $"-L{logPath}");
			args.Add(databasePath);

			var psi = new ProcessStartInfo {
				FileName = launchPath,
				UseShellExecute = false,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				CreateNoWindow = true,
			};
			psi.Arguments = string.Join(" ", args.ConvertAll(QuoteForCommandLine));

			idaProcess = new Process { StartInfo = psi };
			if (!idaProcess.Start())
				throw new InvalidOperationException("Failed to start IDA process for ida-pro-mcp.");
			KilnLog.Info($"ida-pro-mcp auto-start launched: {psi.FileName} {psi.Arguments}");

			_ = Task.Run(async () => {
				try {
					while (!idaProcess.HasExited) {
						var line = await idaProcess.StandardOutput.ReadLineAsync().ConfigureAwait(false);
						if (line is null)
							break;
						if (!string.IsNullOrWhiteSpace(line))
							KilnLog.Info($"ida-mcp: {line}");
					}
				}
				catch {
				}
			});

			_ = Task.Run(async () => {
				try {
					while (!idaProcess.HasExited) {
						var line = await idaProcess.StandardError.ReadLineAsync().ConfigureAwait(false);
						if (line is null)
							break;
						if (!string.IsNullOrWhiteSpace(line))
							KilnLog.Warn($"ida-mcp stderr: {line}");
					}
				}
				catch {
				}
			});
		}

		static string ResolveIdaLaunchPath(string idaPath, bool headless) {
			if (string.IsNullOrWhiteSpace(idaPath))
				return idaPath;
			var name = Path.GetFileName(idaPath);
			if (string.IsNullOrWhiteSpace(name))
				return idaPath;
			var dir = Path.GetDirectoryName(idaPath);
			if (string.IsNullOrWhiteSpace(dir))
				return idaPath;

			if (headless) {
				if (name.Equals("ida.exe", StringComparison.OrdinalIgnoreCase) || name.Equals("ida64.exe", StringComparison.OrdinalIgnoreCase)) {
					var idatCandidate = Path.Combine(dir, name.StartsWith("ida64", StringComparison.OrdinalIgnoreCase) ? "idat64.exe" : "idat.exe");
					if (File.Exists(idatCandidate))
						return idatCandidate;
					return idaPath;
				}
				return idaPath;
			}

			if (!name.Equals("idat.exe", StringComparison.OrdinalIgnoreCase) && !name.Equals("idat64.exe", StringComparison.OrdinalIgnoreCase))
				return idaPath;
			var ida64 = Path.Combine(dir, "ida64.exe");
			if (File.Exists(ida64))
				return ida64;
			var ida = Path.Combine(dir, "ida.exe");
			if (File.Exists(ida))
				return ida;
			return idaPath;
		}

		static bool IsGuiIda(string path) {
			if (string.IsNullOrWhiteSpace(path))
				return false;
			var name = Path.GetFileName(path);
			if (string.IsNullOrWhiteSpace(name))
				return false;
			return name.Equals("ida.exe", StringComparison.OrdinalIgnoreCase)
				|| name.Equals("ida64.exe", StringComparison.OrdinalIgnoreCase);
		}

		string GetAutoScriptPath() {
			if (!string.IsNullOrWhiteSpace(idaAutoScriptPath))
				return idaAutoScriptPath!;
			var root = string.IsNullOrWhiteSpace(config.WorkspaceRoot)
				? Path.Combine(AppContext.BaseDirectory, "workspace")
				: config.WorkspaceRoot;
			Directory.CreateDirectory(root);
			idaAutoScriptPath = Path.Combine(root, "ida_mcp_autostart.py");
			return idaAutoScriptPath;
		}

		static void WriteAutoScript(string path) {
			const string script = 
@"import idaapi
import time

try:
    idaapi.auto_wait()
except Exception:
    pass

def try_start():
    try:
        from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        try:
            init_caches()
        except Exception as e:
            print(""[MCP] Cache init failed: %s"" % e)
        MCP_SERVER.serve(""127.0.0.1"", 13337, request_handler=IdaMcpHttpRequestHandler)
        print(""[MCP] Server started via ida_mcp package"")
        return True
    except Exception:
        pass
    try:
        idaapi.load_and_run_plugin(""MCP"", 0)
        return True
    except Exception:
        pass
    try:
        idaapi.run_plugin(""MCP"", 0)
        return True
    except Exception as e:
        print(""[MCP] Failed to start plugin: %s"" % e)
        return False

for _ in range(60):
    if try_start():
        break
    time.sleep(1)

while True:
    try:
        idaapi.qsleep(1000)
    except Exception:
        time.sleep(1)
";
			File.WriteAllText(path, script, Encoding.ASCII);
		}

		static string BuildScriptInvocation(string scriptPath) {
			var escaped = scriptPath.Replace("\"", "\\\"");
			return $"\"{escaped}\"";
		}

		static string QuoteForCommandLine(string arg) {
			if (string.IsNullOrEmpty(arg))
				return "\"\"";
			var needsQuotes = false;
			for (var i = 0; i < arg.Length; i++) {
				var ch = arg[i];
				if (char.IsWhiteSpace(ch) || ch == '\"') {
					needsQuotes = true;
					break;
				}
			}
			if (!needsQuotes)
				return arg;

			var builder = new StringBuilder();
			builder.Append('\"');
			var backslashes = 0;
			foreach (var ch in arg) {
				if (ch == '\\') {
					backslashes++;
					continue;
				}
				if (ch == '\"') {
					builder.Append('\\', backslashes * 2 + 1);
					builder.Append(ch);
					backslashes = 0;
					continue;
				}
				if (backslashes > 0) {
					builder.Append('\\', backslashes);
					backslashes = 0;
				}
				builder.Append(ch);
			}
			if (backslashes > 0)
				builder.Append('\\', backslashes * 2);
			builder.Append('\"');
			return builder.ToString();
		}

		static IEnumerable<IdaMcpProxyTool> ParseTools(JObject response) {
			var tools = new List<IdaMcpProxyTool>();
			var list = response["result"]?["tools"] as JArray;
			if (list is null)
				return tools;

			foreach (var entry in list.OfType<JObject>()) {
				var name = entry["name"]?.Value<string>();
				if (string.IsNullOrWhiteSpace(name))
					continue;
				var description = entry["description"]?.Value<string>() ?? string.Empty;
				var schema = entry["inputSchema"] as JObject ?? new JObject();
				var normalized = NormalizeSchema(schema);
				tools.Add(new IdaMcpProxyTool(name, description, normalized));
			}
			return tools;
		}

		static JObject NormalizeSchema(JObject schema) {
			var normalized = (JObject)schema.DeepClone();
			var type = normalized["type"]?.Value<string>();
			if (string.IsNullOrWhiteSpace(type))
				normalized["type"] = "object";

			if (normalized["properties"] is not JObject)
				normalized["properties"] = new JObject();

			if (normalized["required"] is not null && normalized["required"]?.Type != JTokenType.Array)
				normalized["required"] = new JArray();

			if (normalized["additionalProperties"] is null)
				normalized["additionalProperties"] = true;

			return normalized;
		}

		static JObject BuildErrorResult(string message) {
			return new JObject {
				["content"] = new JArray {
					new JObject {
						["type"] = "text",
						["text"] = message,
					},
				},
				["isError"] = true,
			};
		}

		public void Dispose() {
			client.Dispose();
			lock (idaGate) {
				if (idaProcess is null)
					return;
				try {
					if (!idaProcess.HasExited)
						idaProcess.Kill(entireProcessTree: true);
				}
				catch {
				}
				idaProcess.Dispose();
				idaProcess = null;
			}
		}
	}

	sealed class IdaMcpProxyTool {
		public string Name { get; }
		public string Description { get; }
		public JObject InputSchema { get; }

		public IdaMcpProxyTool(string name, string description, JObject inputSchema) {
			Name = name;
			Description = description;
			InputSchema = inputSchema;
		}
	}

	sealed class McpStdioClient : IDisposable {
		readonly string command;
		readonly IReadOnlyList<string> args;
		readonly string? workingDir;
		readonly SemaphoreSlim writeLock = new SemaphoreSlim(1, 1);
		readonly SemaphoreSlim initLock = new SemaphoreSlim(1, 1);
		readonly object gate = new object();

		Process? process;
		StreamWriter? stdin;
		StreamReader? stdout;
		Task? readLoop;
		Task? errorLoop;
		CancellationTokenSource? readCts;
		Dictionary<string, TaskCompletionSource<JObject>> pending = new Dictionary<string, TaskCompletionSource<JObject>>();
		int nextId;
		bool initialized;

		public McpStdioClient(string command, IReadOnlyList<string> args, string? workingDir) {
			this.command = command;
			this.args = args ?? Array.Empty<string>();
			this.workingDir = string.IsNullOrWhiteSpace(workingDir) ? null : workingDir;
		}

		public async Task EnsureInitializedAsync(CancellationToken token, TimeSpan timeout) {
			if (IsProcessHealthy() && initialized)
				return;

			await initLock.WaitAsync(token).ConfigureAwait(false);
			try {
				if (IsProcessHealthy() && initialized)
					return;

				StartProcess();
				await InitializeAsync(token, timeout).ConfigureAwait(false);
				initialized = true;
			}
			finally {
				initLock.Release();
			}
		}

		async Task InitializeAsync(CancellationToken token, TimeSpan timeout) {
			var initParams = new JObject {
				["protocolVersion"] = "2024-11-05",
				["capabilities"] = new JObject {
					["tools"] = new JObject(),
					["resources"] = new JObject(),
				},
				["clientInfo"] = new JObject {
					["name"] = "Kiln.Mcp",
					["version"] = "0.1.0",
				},
			};
			await SendRequestAsync("initialize", initParams, token, timeout).ConfigureAwait(false);
			await SendNotificationAsync("notifications/initialized", null, token).ConfigureAwait(false);
		}

		public async Task<JObject> SendRequestAsync(string method, JObject? parameters, CancellationToken token, TimeSpan timeout) {
			if (!IsProcessHealthy())
				throw new IOException("ida-pro-mcp process is not running.");

			var id = Interlocked.Increment(ref nextId);
			var idKey = id.ToString(CultureInfo.InvariantCulture);
			var tcs = new TaskCompletionSource<JObject>(TaskCreationOptions.RunContinuationsAsynchronously);
			lock (gate) {
				pending[idKey] = tcs;
			}

			var payload = new JObject {
				["jsonrpc"] = "2.0",
				["id"] = id,
				["method"] = method,
				["params"] = parameters ?? new JObject(),
			};
			var line = payload.ToString(Formatting.None);

			await writeLock.WaitAsync(token).ConfigureAwait(false);
			try {
				await stdin!.WriteLineAsync(line).ConfigureAwait(false);
				await stdin.FlushAsync().ConfigureAwait(false);
			}
			finally {
				writeLock.Release();
			}

			var delay = Task.Delay(timeout, token);
			var completed = await Task.WhenAny(tcs.Task, delay).ConfigureAwait(false);
			if (completed == delay) {
				lock (gate) {
					pending.Remove(idKey);
				}
				if (token.IsCancellationRequested)
					throw new OperationCanceledException(token);
				throw new TimeoutException($"ida-pro-mcp request timed out: {method}");
			}

			return await tcs.Task.ConfigureAwait(false);
		}

		async Task SendNotificationAsync(string method, JObject? parameters, CancellationToken token) {
			if (!IsProcessHealthy())
				return;

			var payload = new JObject {
				["jsonrpc"] = "2.0",
				["method"] = method,
				["params"] = parameters ?? new JObject(),
			};
			var line = payload.ToString(Formatting.None);
			await writeLock.WaitAsync(token).ConfigureAwait(false);
			try {
				await stdin!.WriteLineAsync(line).ConfigureAwait(false);
				await stdin.FlushAsync().ConfigureAwait(false);
			}
			finally {
				writeLock.Release();
			}
		}

		void StartProcess() {
			if (string.IsNullOrWhiteSpace(command))
				throw new InvalidOperationException("ida-pro-mcp command is empty.");

			StopProcess();

			var info = new ProcessStartInfo {
				FileName = command,
				RedirectStandardInput = true,
				RedirectStandardOutput = true,
				RedirectStandardError = true,
				UseShellExecute = false,
				CreateNoWindow = true,
				StandardOutputEncoding = Encoding.UTF8,
				StandardErrorEncoding = Encoding.UTF8,
			};
			if (!string.IsNullOrWhiteSpace(workingDir))
				info.WorkingDirectory = workingDir!;
			foreach (var arg in args)
				info.ArgumentList.Add(arg);

			process = new Process { StartInfo = info };
			if (!process.Start())
				throw new InvalidOperationException("Failed to start ida-pro-mcp process.");

			stdin = process.StandardInput;
			stdout = process.StandardOutput;
			readCts = new CancellationTokenSource();
			readLoop = Task.Run(() => ReadLoopAsync(readCts.Token));
			errorLoop = Task.Run(() => ErrorLoopAsync(readCts.Token));
		}

		bool IsProcessHealthy() =>
			process is not null && !process.HasExited && stdin is not null && stdout is not null;

		async Task ReadLoopAsync(CancellationToken token) {
			try {
				while (!token.IsCancellationRequested) {
					var line = await stdout!.ReadLineAsync().ConfigureAwait(false);
					if (line is null)
						break;
					if (string.IsNullOrWhiteSpace(line))
						continue;

					JObject message;
					try {
						message = JObject.Parse(line);
					}
					catch (JsonException) {
						KilnLog.Warn("ida-pro-mcp stdio parse error");
						continue;
					}

					var idToken = message["id"];
					if (idToken is null)
						continue;
					var idKey = idToken.Type == JTokenType.String
						? idToken.Value<string>() ?? string.Empty
						: idToken.ToString(Formatting.None);
					if (string.IsNullOrWhiteSpace(idKey))
						continue;

					TaskCompletionSource<JObject>? tcs = null;
					lock (gate) {
						if (pending.TryGetValue(idKey, out tcs))
							pending.Remove(idKey);
					}
					tcs?.TrySetResult(message);
				}
			}
			finally {
				FailPending("ida-pro-mcp process disconnected.");
				initialized = false;
			}
		}

		async Task ErrorLoopAsync(CancellationToken token) {
			try {
				while (!token.IsCancellationRequested) {
					var line = await process!.StandardError.ReadLineAsync().ConfigureAwait(false);
					if (line is null)
						break;
					if (!string.IsNullOrWhiteSpace(line))
						KilnLog.Warn($"ida-pro-mcp stderr: {line}");
				}
			}
			catch {
			}
		}

		void FailPending(string message) {
			List<TaskCompletionSource<JObject>> pendingTasks;
			lock (gate) {
				pendingTasks = pending.Values.ToList();
				pending.Clear();
			}
			foreach (var tcs in pendingTasks)
				tcs.TrySetException(new IOException(message));
		}

		void StopProcess() {
			initialized = false;
			readCts?.Cancel();
			readCts?.Dispose();
			readCts = null;

			if (process is not null) {
				try {
					if (!process.HasExited)
						process.Kill(entireProcessTree: true);
				}
				catch {
				}
				process.Dispose();
			}

			process = null;
			stdin = null;
			stdout = null;
			readLoop = null;
			errorLoop = null;
		}

		public void Dispose() {
			StopProcess();
			writeLock.Dispose();
			initLock.Dispose();
		}
	}
}
