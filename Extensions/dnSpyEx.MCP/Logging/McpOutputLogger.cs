using System;
using System.Windows;
using dnSpy.Contracts.Output;
using dnSpy.Contracts.Text;

namespace dnSpyEx.MCP.Logging {
	sealed class McpOutputLogger : IMcpLogger {
		readonly IOutputService outputService;
		readonly Guid paneGuid;
		readonly string paneName;

		public McpOutputLogger(IOutputService outputService, Guid paneGuid, string paneName) {
			this.outputService = outputService;
			this.paneGuid = paneGuid;
			this.paneName = paneName;
		}

		public void Info(string message) => Write(BoxedTextColor.Text, message);
		public void Warn(string message) => Write(BoxedTextColor.Comment, message);
		public void Error(string message) => Write(BoxedTextColor.Error, message);

		void Write(object color, string message) {
			RunOnUi(() => {
				var pane = outputService.Create(paneGuid, paneName, ContentTypes.Text);
				pane.WriteLine(color, message);
			});
		}

		static void RunOnUi(Action action) {
			var dispatcher = Application.Current?.Dispatcher;
			if (dispatcher is null || dispatcher.CheckAccess()) {
				action();
				return;
			}
			dispatcher.Invoke(action);
		}
	}
}
