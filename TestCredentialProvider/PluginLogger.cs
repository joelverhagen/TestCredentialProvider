using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading.Channels;
using Newtonsoft.Json;
using NuGet.Common;
using NuGet.Protocol.Plugins;

namespace NuGet.Protocol.TokenCredentialProvider;

class PluginLogger : IDisposable
{
    private readonly Stopwatch _started;
    private readonly Channel<(LogLevel Level, string Message)> _messages;
    private readonly CancellationTokenSource _stopCts;
    private readonly ConcurrentBag<string> _redacted;
    private readonly Lazy<Task> _lazyFlush;

    public PluginLogger()
    {
        _started = Stopwatch.StartNew();
        _messages = Channel.CreateUnbounded<(LogLevel Level, string Message)>(new UnboundedChannelOptions
        {
            AllowSynchronousContinuations = false,
            SingleReader = true,
            SingleWriter = false,
        });
        _stopCts = new();
        _redacted = new();
        _lazyFlush = new Lazy<Task>(PumpAsync);
    }

    public IPlugin? Plugin { get; set; }
    public LogLevel LogLevel { get; set; } = LogLevel.Debug;

    public void Redact(string value)
    {
        _redacted.Add(value);
    }

    public void Dispose()
    {
        try
        {
            _stopCts.Cancel();
        }
        catch
        {
            // ignore
        }

        _stopCts.Dispose();
    }

    public void Log(LogLevel level, string message)
    {
        var pid = Process.GetCurrentProcess().Id;
        var levelPrefix = level.ToString().ToUpperInvariant().Substring(0, 3);

        foreach (var value in _redacted)
        {
            message.Replace(value, "REDACTED", StringComparison.OrdinalIgnoreCase);
            message.Replace(System.Text.Json.JsonSerializer.Serialize(value), "\"REDACTED\"", StringComparison.OrdinalIgnoreCase);
            message.Replace(JsonConvert.SerializeObject(value), "\"REDACTED\"", StringComparison.OrdinalIgnoreCase);
        }

        LogToFile($"[oidc-login {pid} {_started.Elapsed.TotalSeconds:0.000} {levelPrefix}] {message}");
        _messages.Writer.TryWrite((level, $"    [oidc-login] {message}"));
    }

    public void Start()
    {
        var _ = _lazyFlush.Value;
    }

    public async Task PauseForEmptyAsync(TimeSpan delay)
    {
        var sw = Stopwatch.StartNew();
        while (_lazyFlush.IsValueCreated && sw.Elapsed < delay && _messages.Reader.TryPeek(out _))
        {
            await Task.Delay(TimeSpan.FromMilliseconds(10));
        }
    }

    public async Task StopAsync(TimeSpan delay)
    {
        if (!_lazyFlush.IsValueCreated)
        {
            return;
        }

        _messages.Writer.TryComplete();
        _stopCts.CancelAfter(delay);
        try
        {
            await _lazyFlush.Value;
        }
        catch (OperationCanceledException)
        {
            // ignore
        }
    }

    private async Task PumpAsync()
    {
        await foreach (var (level, message) in _messages.Reader.ReadAllAsync(_stopCts.Token))
        {
            if (level < LogLevel)
            {
                continue;
            }

            var plugin = Plugin;
            if (plugin is null)
            {
                continue;
            }

            try
            {
                await plugin.Connection.SendRequestAndReceiveResponseAsync<LogRequest, LogResponse>(
                    MessageMethod.Log,
                    new LogRequest(level, message),
                    _stopCts.Token);
            }
            catch (OperationCanceledException)
            {
                // ignore
            }
            catch (Exception ex)
            {
                LogToFile("Logging error: " + ex);
            }
        }
    }

    private static void LogToFile(string message)
    {
        try
        {
            File.AppendAllLines("TestCredentialProvider.log.txt", new[] { message });
        }
        catch
        {
            // best effort
        }
    }
}
