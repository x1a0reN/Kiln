using System;
using System.Threading;
using System.Threading.Tasks;

namespace dnSpyEx.MCP.Bridge {
	static class Program {
		static async Task<int> Main(string[] args) {
			try {
				var pipeName = GetPipeName(args);
				BridgeLog.Info($"bridge start (pipe={pipeName})");
				using var client = new PipeClient(pipeName);
				using var cts = new CancellationTokenSource();
				Console.CancelKeyPress += (_, e) => {
					e.Cancel = true;
					cts.Cancel();
				};

				var server = new McpServer(client);
				await server.RunAsync(cts.Token).ConfigureAwait(false);
				return 0;
			}
			catch (OperationCanceledException) {
				BridgeLog.Warn("bridge canceled");
				return 1;
			}
			catch (Exception ex) {
				BridgeLog.Error($"bridge fatal: {ex}");
				Console.Error.WriteLine(ex.Message);
				return 2;
			}
		}

		static string GetPipeName(string[] args) {
			for (int i = 0; i < args.Length - 1; i++) {
				if (string.Equals(args[i], "--pipe", StringComparison.OrdinalIgnoreCase))
					return args[i + 1];
			}

			var env = Environment.GetEnvironmentVariable(McpPipeDefaults.PipeEnvVar);
			return string.IsNullOrWhiteSpace(env) ? McpPipeDefaults.DefaultPipeName : env;
		}
	}
}
