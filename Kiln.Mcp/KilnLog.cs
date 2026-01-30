using System;
using System.IO;

namespace Kiln.Mcp {
	static class KilnLog {
		static readonly string? LogPath = Environment.GetEnvironmentVariable("KILN_MCP_LOG");
		static readonly object Gate = new object();

		public static void Info(string message) => Write("INFO", message);
		public static void Warn(string message) => Write("WARN", message);
		public static void Error(string message) => Write("ERROR", message);

		static void Write(string level, string message) {
			if (string.IsNullOrWhiteSpace(LogPath))
				return;
			var line = $"{DateTime.Now:HH:mm:ss.fff} [{level}] {message}{Environment.NewLine}";
			try {
				lock (Gate) {
					File.AppendAllText(LogPath!, line);
				}
			}
			catch {
			}
		}
	}
}
