namespace Kiln.Plugins.Unity.Il2Cpp {
	public sealed record Il2CppDumpResult(
		bool Success,
		int ExitCode,
		string GameAssemblyPath,
		string MetadataPath,
		string OutputDir,
		string StdOut,
		string StdErr
	);
}
