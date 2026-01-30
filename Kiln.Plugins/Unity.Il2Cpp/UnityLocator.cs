using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;

namespace Kiln.Plugins.Unity.Il2Cpp {
	public static class UnityLocator {
		static readonly EnumerationOptions RecursiveOptions = new EnumerationOptions {
			RecurseSubdirectories = true,
			IgnoreInaccessible = true,
		};

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

			return EnumerateFilesSafe(gameDir, "GameAssembly.dll")
				.FirstOrDefault();
		}

		static string? FindGlobalMetadata(string gameDir, out string? dataDir) {
			dataDir = null;
			var metadata = EnumerateFilesSafe(gameDir, "global-metadata.dat")
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
			var managed = EnumerateFilesSafe(gameDir, "Assembly-CSharp.dll")
				.FirstOrDefault(path => path.IndexOf($"{Path.DirectorySeparatorChar}Managed{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) >= 0);

			if (managed is null)
				return null;

			return Path.GetDirectoryName(managed);
		}

		static IEnumerable<string> EnumerateFilesSafe(string gameDir, string pattern) {
			try {
				return Directory.EnumerateFiles(gameDir, pattern, RecursiveOptions);
			}
			catch (Exception ex) when (ex is UnauthorizedAccessException || ex is PathTooLongException || ex is IOException || ex is SecurityException) {
				return Array.Empty<string>();
			}
		}
	}
}
