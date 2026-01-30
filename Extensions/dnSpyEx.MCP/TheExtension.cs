using System.Collections.Generic;
using System.ComponentModel.Composition;
using dnSpy.Contracts.Extension;

namespace dnSpyEx.MCP {
	[ExportExtension]
	sealed class TheExtension : IExtension {
		readonly McpHost host;

		[ImportingConstructor]
		TheExtension(McpHost host) => this.host = host;

		public IEnumerable<string> MergedResourceDictionaries {
			get { yield break; }
		}

		public ExtensionInfo ExtensionInfo => new ExtensionInfo {
			ShortDescription = "dnSpyEx MCP bridge",
		};

		public void OnEvent(ExtensionEvent @event, object? obj) {
			if (@event == ExtensionEvent.AppLoaded)
				host.Start();
			else if (@event == ExtensionEvent.AppExit)
				host.Dispose();
		}
	}
}
