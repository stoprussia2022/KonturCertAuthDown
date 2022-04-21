using KonturCertAuthDown;

if (args.Length == 0 || !int.TryParse(args[0], out var jobsCount)) jobsCount = 1000;
var jobs = Enumerable.Range(0, jobsCount).Select(_ => new Job(certificateRandomBase64StringBytesCount: 700)).ToArray();

Console.WriteLine($"Start {jobsCount} jobs.");
DumpStats();

var tasks = jobs.Select(j => j.DoAuthAsync());

await Task.WhenAll(tasks);

async void DumpStats()
{
    while (true)
    {
        await Task.Delay(3000);

        long totalSuccessRequestsCount = 0;
        long totalFailedRequestsCount = 0;
        long avgLastSuccessRequestDurationMs = 0;
        foreach (var job in jobs)
        {
            var (successRequestsCount, failedRequestsCount, lastSuccessDurationMs) = job.Stats;
            totalSuccessRequestsCount += successRequestsCount;
            totalFailedRequestsCount += failedRequestsCount;
            avgLastSuccessRequestDurationMs += lastSuccessDurationMs;
        }

        avgLastSuccessRequestDurationMs /= jobsCount;
        Console.WriteLine(
            $"    Success requests: {totalSuccessRequestsCount} (avg {avgLastSuccessRequestDurationMs}ms); failed requests: {totalFailedRequestsCount}."
        );
    }
}