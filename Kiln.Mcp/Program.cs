using System;
using System.Threading;
using System.Threading.Tasks;

namespace Kiln.Mcp {
	static class Program {
		static async Task<int> Main(string[] args) {
			try {
				KilnLog.Info("kiln mcp start");
				using var cts = new CancellationTokenSource();
				Console.CancelKeyPress += (_, e) => {
					e.Cancel = true;
					cts.Cancel();
				};

				var server = new McpServer();
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
	}
}
