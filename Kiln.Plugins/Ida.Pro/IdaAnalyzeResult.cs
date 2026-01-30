namespace Kiln.Plugins.Ida.Pro {
	public sealed record IdaAnalyzeResult(
		bool Success,
		int ExitCode,
		string InputBinaryPath,
		string DatabasePath,
		string LogPath,
		string StdOut,
		string StdErr
	);
}
