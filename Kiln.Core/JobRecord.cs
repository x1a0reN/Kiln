using System;

namespace Kiln.Core {
	public sealed class JobRecord {
		public string JobId { get; init; } = string.Empty;
		public string FlowName { get; init; } = string.Empty;
		public string ParamsJson { get; init; } = "{}";
		public JobState State { get; set; } = JobState.Pending;
		public string Stage { get; set; } = "created";
		public int Percent { get; set; }
		public DateTime CreatedUtc { get; init; } = DateTime.UtcNow;
		public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;
		public string? Error { get; set; }
	}
}
