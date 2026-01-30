namespace Kiln.Core {
	public enum JobState {
		Pending,
		Running,
		Completed,
		Failed,
		Canceled,
	}

	public sealed record JobInfo(
		string JobId,
		JobState State,
		string Stage,
		int Percent
	);
}
