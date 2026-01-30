using System.Collections.Generic;

namespace Kiln.Plugins.Packaging {
	public sealed record PatchCodegenResult(
		string OutputDir,
		IReadOnlyList<string> Files
	);
}
