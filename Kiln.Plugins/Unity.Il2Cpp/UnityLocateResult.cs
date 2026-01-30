namespace Kiln.Plugins.Unity.Il2Cpp {
	public sealed record UnityLocateResult(
		string GameDir,
		string? GameAssemblyPath,
		string? MetadataPath,
		string? DataDir,
		string? ManagedDir,
		bool IsIl2Cpp,
		bool IsMono,
		string? Notes
	);
}
