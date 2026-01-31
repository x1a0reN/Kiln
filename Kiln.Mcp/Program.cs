using System;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;
using System.Threading;
using System.Threading.Tasks;
using Kiln.Core;

namespace Kiln.Mcp {
	static class Program {
		static async Task<int> Main(string[] args) {
			try {
				RegisterPluginResolver();
				KilnLog.Info("kiln mcp start");
				var config = KilnConfig.Load();
				var jobManager = new JobManager(config);
				using var cts = new CancellationTokenSource();
				Console.CancelKeyPress += (_, e) => {
					e.Cancel = true;
					cts.Cancel();
				};

				var server = new McpServer(jobManager, config);
				await server.RunAsync(cts.Token).ConfigureAwait(false);
				return 0;
			}
			catch (OperationCanceledException) {
				KilnLog.Warn("kiln mcp canceled");
				return 1;
			}
			catch (Exception ex) {
				KilnLog.Error($"kiln mcp fatal: {ex}");
				Console.Error.WriteLine(ex.Message);
				return 2;
			}
		}

		static void RegisterPluginResolver() {
			var baseDir = AppContext.BaseDirectory;
			var pluginsDir = Path.Combine(baseDir, "Plugins");
			if (!Directory.Exists(pluginsDir))
				return;

			AssemblyLoadContext.Default.Resolving += (_, name) => {
				if (string.IsNullOrWhiteSpace(name.Name))
					return null;
				var candidate = Path.Combine(pluginsDir, $"{name.Name}.dll");
				if (File.Exists(candidate))
					return AssemblyLoadContext.Default.LoadFromAssemblyPath(candidate);
				return null;
			};
		}
	}
}
