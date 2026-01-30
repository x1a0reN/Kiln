using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Kiln.Core {
	public sealed class JobManager {
		readonly string workspaceRoot;
		readonly Dictionary<string, JobRecord> jobs = new(StringComparer.OrdinalIgnoreCase);
		readonly Dictionary<string, CancellationTokenSource> cancellations = new(StringComparer.OrdinalIgnoreCase);
		readonly object gate = new();
		readonly JsonSerializerOptions jsonOptions = new() {
			WriteIndented = true,
			Converters = { new JsonStringEnumConverter() },
		};

		public JobManager(KilnConfig config) {
			if (config is null)
				throw new ArgumentNullException(nameof(config));
			workspaceRoot = config.WorkspaceRoot;
			Directory.CreateDirectory(workspaceRoot);
		}

		public JobRecord StartWorkflow(string flowName, string paramsJson) {
			if (string.IsNullOrWhiteSpace(flowName))
				throw new ArgumentException("flowName is required", nameof(flowName));

			return StartJob(flowName, paramsJson, RunStubWorkflowAsync);
		}

		public JobRecord StartJob(string flowName, string paramsJson, Func<JobContext, Task> runner) {
			if (string.IsNullOrWhiteSpace(flowName))
				throw new ArgumentException("flowName is required", nameof(flowName));
			if (runner is null)
				throw new ArgumentNullException(nameof(runner));

			var job = CreateJob(flowName, paramsJson);
			var cts = new CancellationTokenSource();
			lock (gate) {
				cancellations[job.JobId] = cts;
			}

			_ = Task.Run(async () => {
				var context = new JobContext(this, job.JobId, cts.Token);
				try {
					await runner(context).ConfigureAwait(false);
				}
				catch (OperationCanceledException) {
					context.Log("Job canceled.");
				}
				catch (Exception ex) {
					context.Log($"Job failed: {ex.Message}");
					context.Update(JobState.Failed, "failed", 100, ex.Message);
				}
			});

			return job;
		}

		public bool TryGetStatus(string jobId, out JobInfo info) {
			if (!TryGetJob(jobId, out var job)) {
				info = new JobInfo(string.Empty, JobState.Failed, "missing", 0);
				return false;
			}

			info = new JobInfo(job.JobId, job.State, job.Stage, job.Percent);
			return true;
		}

		public bool TryReadLogs(string jobId, int tail, out string logs) {
			if (!TryGetJob(jobId, out _)) {
				logs = string.Empty;
				return false;
			}

			var logPath = GetLogPath(jobId);
			if (!File.Exists(logPath)) {
				logs = string.Empty;
				return true;
			}

			var lines = File.ReadAllLines(logPath);
			if (tail <= 0 || tail >= lines.Length) {
				logs = string.Join(Environment.NewLine, lines);
				return true;
			}

			var slice = new string[tail];
			Array.Copy(lines, lines.Length - tail, slice, 0, tail);
			logs = string.Join(Environment.NewLine, slice);
			return true;
		}

		public bool TryCancel(string jobId, out JobInfo info) {
			if (!TryGetJob(jobId, out var job)) {
				info = new JobInfo(string.Empty, JobState.Failed, "missing", 0);
				return false;
			}

			lock (gate) {
				if (job.State is JobState.Completed or JobState.Failed or JobState.Canceled) {
					info = new JobInfo(job.JobId, job.State, job.Stage, job.Percent);
					return true;
				}

				job.State = JobState.Canceled;
				job.Stage = "canceled";
				job.UpdatedUtc = DateTime.UtcNow;
				job.Error = "Canceled";
				SaveJob(job);
				AppendLog(job.JobId, "Job canceled.");
				if (cancellations.TryGetValue(jobId, out var cts))
					cts.Cancel();
				info = new JobInfo(job.JobId, job.State, job.Stage, job.Percent);
				return true;
			}
		}

		JobRecord CreateJob(string flowName, string paramsJson) {
			var job = new JobRecord {
				JobId = Guid.NewGuid().ToString("N"),
				FlowName = flowName.Trim(),
				ParamsJson = string.IsNullOrWhiteSpace(paramsJson) ? "{}" : paramsJson,
				State = JobState.Pending,
				Stage = "created",
				Percent = 0,
				CreatedUtc = DateTime.UtcNow,
				UpdatedUtc = DateTime.UtcNow,
			};

			lock (gate) {
				jobs[job.JobId] = job;
				SaveJob(job);
				AppendLog(job.JobId, $"Job created for flow '{job.FlowName}'.");
			}

			return job;
		}

		async Task RunStubWorkflowAsync(JobContext context) {
			context.Update(JobState.Running, "running", 5, null);
			context.Log("Workflow stub started.");

			try {
				await Task.Delay(300, context.Token).ConfigureAwait(false);
			}
			catch (OperationCanceledException) {
				return;
			}

			context.Update(JobState.Completed, "completed", 100, null);
			context.Log("Workflow stub completed.");
		}

		void UpdateJob(string jobId, JobState state, string stage, int percent, string? error) {
			lock (gate) {
				if (!jobs.TryGetValue(jobId, out var job))
					return;
				if (job.State is JobState.Canceled or JobState.Failed)
					return;

				job.State = state;
				job.Stage = stage;
				job.Percent = Math.Clamp(percent, 0, 100);
				job.UpdatedUtc = DateTime.UtcNow;
				job.Error = error;
				SaveJob(job);
			}
		}

		bool TryGetJob(string jobId, out JobRecord job) {
			if (string.IsNullOrWhiteSpace(jobId)) {
				job = new JobRecord();
				return false;
			}

			lock (gate) {
				if (jobs.TryGetValue(jobId, out var cached) && cached is not null) {
					job = cached;
					return true;
				}
			}

			var jobPath = GetJobPath(jobId);
			if (!File.Exists(jobPath)) {
				job = new JobRecord();
				return false;
			}

			try {
				var json = File.ReadAllText(jobPath);
				var loaded = JsonSerializer.Deserialize<JobRecord>(json, jsonOptions);
				if (loaded is null) {
					job = new JobRecord();
					return false;
				}

				lock (gate) {
					jobs[jobId] = loaded;
				}
				job = loaded;
				return true;
			}
			catch {
				job = new JobRecord();
				return false;
			}
		}

		void SaveJob(JobRecord job) {
			var jobDir = GetJobDir(job.JobId);
			Directory.CreateDirectory(jobDir);
			var json = JsonSerializer.Serialize(job, jsonOptions);
			File.WriteAllText(GetJobPath(job.JobId), json);
		}

		void AppendLog(string jobId, string message) {
			var jobDir = GetJobDir(jobId);
			Directory.CreateDirectory(jobDir);
			var line = $"{DateTime.Now:HH:mm:ss} {message}{Environment.NewLine}";
			File.AppendAllText(GetLogPath(jobId), line);
		}

		string GetJobDir(string jobId) => Path.Combine(workspaceRoot, jobId);
		string GetJobPath(string jobId) => Path.Combine(GetJobDir(jobId), "job.json");
		string GetLogPath(string jobId) => Path.Combine(GetJobDir(jobId), "job.log");

		public sealed class JobContext {
			readonly JobManager manager;

			internal JobContext(JobManager manager, string jobId, CancellationToken token) {
				this.manager = manager;
				JobId = jobId;
				Token = token;
			}

			public string JobId { get; }
			public CancellationToken Token { get; }

			public void Update(JobState state, string stage, int percent, string? error) {
				manager.UpdateJob(JobId, state, stage, percent, error);
			}

			public void Log(string message) {
				manager.AppendLog(JobId, message);
			}
		}
	}
}
