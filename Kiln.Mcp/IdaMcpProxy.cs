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
		readonly object cacheGate = new object();
		List<IdaMcpProxyTool> cachedTools = new List<IdaMcpProxyTool>();
		DateTime lastSyncUtc = DateTime.MinValue;

		public bool Enabled { get; }
		public string Prefix => ToolPrefix;

		IdaMcpProxy(KilnConfig config) {
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
