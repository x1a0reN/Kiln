using System.Collections.Generic;

namespace Kiln.Plugins.Packaging {
	public sealed record PackageModResult(
		string OutputDir,
		string ManifestPath,
		string InstallPath,
		string RollbackPath,
		string PackagePath,
		IReadOnlyList<string> PayloadFiles
	);
}
