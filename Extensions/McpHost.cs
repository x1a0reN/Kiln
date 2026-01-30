using System;
using System.ComponentModel.Composition;
using System.Windows;
using System.Windows.Threading;
using dnSpy.Contracts.Decompiler;
using dnSpy.Contracts.Documents.Tabs;
using dnSpy.Contracts.Output;
using dnSpyEx.MCP.Logging;
using dnSpyEx.MCP.Ipc;

namespace dnSpyEx.MCP {
	[Export]
	sealed class McpHost : IDisposable {
		readonly McpIpcServer server;
		readonly DispatcherUnhandledExceptionEventHandler dispatcherHandler;

		[ImportingConstructor]
		McpHost(IDocumentTabService documentTabService, IDecompilerService decompilerService, IOutputService outputService) {
			var logger = new McpOutputLogger(outputService, OutputPaneGuid, OutputPaneName);
			var handler = new McpRequestHandler(documentTabService, decompilerService, logger);
			server = new McpIpcServer(handler, logger);

			dispatcherHandler = (_, e) => {
				if (e.Exception is NullReferenceException &&
					e.Exception.StackTrace?.Contains("dnSpy.BamlDecompiler.BamlTabSaver") == true) {
					logger.Warn("Suppressed BamlTabSaver NullReferenceException");
					e.Handled = true;
				}
			};
			Application.Current?.DispatcherUnhandledException += dispatcherHandler;
		}

		public void Start() => server.Start();

		public void Dispose() {
			server.Dispose();
			Application.Current?.DispatcherUnhandledException -= dispatcherHandler;
		}

		static readonly Guid OutputPaneGuid = new Guid("A73D6DE4-0D0A-4D03-9E93-7F7A1D4D0E5C");
		const string OutputPaneName = "dnSpyEx.MCP";
	}
}
