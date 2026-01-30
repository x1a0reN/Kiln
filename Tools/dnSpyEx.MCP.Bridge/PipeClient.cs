using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace dnSpyEx.MCP.Bridge {
	sealed class PipeClient : IDisposable {
		const int DefaultConnectTimeoutSeconds = 10;

		readonly string pipeName;
		NamedPipeClientStream? pipe;
		StreamReader? reader;
		StreamWriter? writer;
		readonly SemaphoreSlim gate = new SemaphoreSlim(1, 1);

		public PipeClient(string pipeName) {
			this.pipeName = string.IsNullOrWhiteSpace(pipeName) ? McpPipeDefaults.DefaultPipeName : pipeName;
		}

		public async Task<JObject> CallAsync(JObject request, CancellationToken token) {
			await gate.WaitAsync(token).ConfigureAwait(false);
			try {
				BridgeLog.Info($"pipe call start: {request["method"]?.Value<string>() ?? "(null)"}");
				return await CallCoreAsync(request, token, allowRetry: true).ConfigureAwait(false);
			}
			finally {
				gate.Release();
			}
		}

		async Task<JObject> CallCoreAsync(JObject request, CancellationToken token, bool allowRetry) {
			try {
				await EnsureConnectedAsync(token).ConfigureAwait(false);
				var lineRequest = request.ToString(Formatting.None);
				BridgeLog.Info($"pipe write ({lineRequest.Length} bytes)");
				await writer!.WriteLineAsync(lineRequest).ConfigureAwait(false);
				BridgeLog.Info("pipe read await");
				var line = await reader!.ReadLineAsync().ConfigureAwait(false);
				if (line is null) {
					BridgeLog.Warn("pipe read EOF");
					throw new IOException("Pipe closed");
				}
				BridgeLog.Info($"pipe read ({line.Length} bytes)");
				return JObject.Parse(line);
			}
			catch (IOException) when (allowRetry) {
				BridgeLog.Warn("pipe io error, retrying once");
				ResetPipe();
				return await CallCoreAsync(request, token, allowRetry: false).ConfigureAwait(false);
			}
			catch (Exception ex) {
				BridgeLog.Error($"pipe call failed: {ex.GetType().Name}: {ex.Message}");
				throw;
			}
		}

		async Task EnsureConnectedAsync(CancellationToken token) {
			if (pipe is not null && pipe.IsConnected)
				return;

			ResetPipe();
			pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
			BridgeLog.Info($"pipe connecting: {pipeName}");
			using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
			cts.CancelAfter(TimeSpan.FromSeconds(DefaultConnectTimeoutSeconds));
			try {
				await pipe.ConnectAsync(cts.Token).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (!token.IsCancellationRequested) {
				throw new TimeoutException($"Timed out connecting to pipe '{pipeName}'.");
			}
			catch {
				ResetPipe();
				throw;
			}

			var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
			reader = new StreamReader(pipe, encoding, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
			writer = new StreamWriter(pipe, encoding, bufferSize: 4096, leaveOpen: true) { AutoFlush = true };
			BridgeLog.Info("pipe connected");
		}

		void ResetPipe() {
			try { writer?.Dispose(); } catch { }
			try { reader?.Dispose(); } catch { }
			try { pipe?.Dispose(); } catch { }
			writer = null;
			reader = null;
			pipe = null;
		}

		public void Dispose() {
			ResetPipe();
			gate.Dispose();
		}
	}
}
