namespace dnSpyEx.MCP.Logging {
	interface IMcpLogger {
		void Info(string message);
		void Warn(string message);
		void Error(string message);
	}
}
