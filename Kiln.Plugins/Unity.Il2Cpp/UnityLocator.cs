using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Kiln.Plugins.Unity.Il2Cpp {
	public static class UnityLocator {
		public static UnityLocateResult Locate(string gameDir) {
			if (string.IsNullOrWhiteSpace(gameDir) || !Directory.Exists(gameDir)) {
				return new UnityLocateResult(
					gameDir ?? string.Empty,
					null,
					null,
					null,
					null,
					false,
					false,
					"gameDir not found"
				);
			}

			var gameAssembly = FindGameAssembly(gameDir);
			var metadata = FindGlobalMetadata(gameDir, out var dataDir);
			var managedDir = FindManagedDir(gameDir);

			var isIl2Cpp = !string.IsNullOrWhiteSpace(gameAssembly) && !string.IsNullOrWhiteSpace(metadata);
			var isMono = !string.IsNullOrWhiteSpace(managedDir);

			var notes = new List<string>();
			if (!isIl2Cpp && !isMono)
				notes.Add("No Unity IL2CPP or Mono artifacts detected.");
			if (!string.IsNullOrWhiteSpace(gameAssembly) && string.IsNullOrWhiteSpace(metadata))
				notes.Add("GameAssembly.dll found but global-metadata.dat not found.");

			return new UnityLocateResult(
				gameDir,
				gameAssembly,
				metadata,
				dataDir,
				managedDir,
				isIl2Cpp,
				isMono,
				notes.Count == 0 ? null : string.Join(" ", notes)
			);
		}

		static string? FindGameAssembly(string gameDir) {
			var direct = Path.Combine(gameDir, "GameAssembly.dll");
			if (File.Exists(direct))
				return direct;

			return Directory.EnumerateFiles(gameDir, "GameAssembly.dll", SearchOption.AllDirectories)
				.FirstOrDefault();
		}

		static string? FindGlobalMetadata(string gameDir, out string? dataDir) {
			dataDir = null;
			var metadata = Directory.EnumerateFiles(gameDir, "global-metadata.dat", SearchOption.AllDirectories)
				.FirstOrDefault(path => path.IndexOf($"{Path.DirectorySeparatorChar}il2cpp_data{Path.DirectorySeparatorChar}Metadata{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) >= 0);

			if (metadata is null)
				return null;

			try {
				var metadataDir = Path.GetDirectoryName(metadata);
				var il2cppDir = metadataDir is null ? null : Directory.GetParent(metadataDir);
				var dataRoot = il2cppDir?.Parent;
				dataDir = dataRoot?.FullName;
			}
			catch {
				dataDir = null;
			}

			return metadata;
		}

		static string? FindManagedDir(string gameDir) {
			var managed = Directory.EnumerateFiles(gameDir, "Assembly-CSharp.dll", SearchOption.AllDirectories)
				.FirstOrDefault(path => path.IndexOf($"{Path.DirectorySeparatorChar}Managed{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) >= 0);

			if (managed is null)
				return null;

			return Path.GetDirectoryName(managed);
		}
	}
}
