using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Threading.Channels;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NuGet.Common;
using NuGet.Protocol.Plugins;

internal class Program
{
    private static async Task<int> Main(string[] args)
    {
        using var cts = new CancellationTokenSource();
        using var logger = new PluginLogger();

        Console.CancelKeyPress += (_, _) => cts.Cancel();

        if (args.Length == 1 && args[0] == "-Plugin")
        {
            var requestHandlers = new RequestHandlerCollection
            {
                { MessageMethod.Initialize, new InitializeRequestHandler(logger) },
                { MessageMethod.GetOperationClaims, new GetOperationClaimsRequestHandler(logger) },
                { MessageMethod.SetLogLevel, new SetLogLevelRequestHandler(logger) },
                { MessageMethod.GetAuthenticationCredentials, new GetAuthenticationCredentialsRequestHandler(logger) },
                { MessageMethod.SetCredentials, new SetCredentialsRequestHandler(logger) },
            };

            using var plugin = await PluginFactory.CreateFromCurrentProcessAsync(
                requestHandlers,
                ConnectionOptions.CreateDefault(),
                cts.Token);

            logger.Plugin = plugin;

            var closedTaskCompletionSource = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            plugin.Closed += (_, _) => closedTaskCompletionSource.TrySetResult();

            await closedTaskCompletionSource.Task;
            await logger.StopAsync(TimeSpan.FromSeconds(5));
            return 0;
        }
        else
        {
            Console.Error.WriteLine($"A single argument '-Plugin' is expected. Received {args.Length} arguments.");
            if (args.Length > 0)
            {
                Console.Error.WriteLine($"  {string.Join(' ', args)}");
            }

            return 1;
        }
    }
}

class PluginLogger : IDisposable
{
    private readonly Stopwatch _started;
    private readonly Channel<(LogLevel Level, string Message)> _messages;
    private readonly CancellationTokenSource _stopCts;
    private Lazy<Task> _lazyFlush;

    public PluginLogger()
    {
        _started = Stopwatch.StartNew();
        _messages = Channel.CreateUnbounded<(LogLevel Level, string Message)>(new UnboundedChannelOptions
        {
            AllowSynchronousContinuations = false,
            SingleReader = true,
            SingleWriter = false,
        });
        _stopCts = new CancellationTokenSource();
        _lazyFlush = new Lazy<Task>(FlushAsync);
    }

    public IPlugin? Plugin { get; set; }
    public LogLevel LogLevel { get; set; } = LogLevel.Debug;

    public void Dispose()
    {
        try
        {
            _stopCts.Cancel();
        }
        catch
        {
            //
        }

        _stopCts.Dispose();
    }

    public void Log(LogLevel level, string message)
    {
        var pid = Process.GetCurrentProcess().Id;
        var levelPrefix = level.ToString().ToUpperInvariant().Substring(0, 3);
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

    private async Task FlushAsync()
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

class InitializeRequestHandler : RequestHandlerBase<InitializeRequest, InitializeResponse>
{
    public InitializeRequestHandler(PluginLogger logger) : base(logger)
    {
    }

    public override Task<InitializeResponse> HandleRequestAsync(InitializeRequest request, CancellationToken cancellationToken)
    {
        return Task.FromResult(new InitializeResponse(MessageResponseCode.Success));
    }
}

class GetOperationClaimsRequestHandler : RequestHandlerBase<GetOperationClaimsRequest, GetOperationClaimsResponse>
{
    public GetOperationClaimsRequestHandler(PluginLogger logger) : base(logger)
    {
    }

    public override Task<GetOperationClaimsResponse> HandleRequestAsync(GetOperationClaimsRequest request, CancellationToken cancellationToken)
    {
        if (request.ServiceIndex is null && request.PackageSourceRepository is null)
        {
            return Task.FromResult(new GetOperationClaimsResponse(new[] { OperationClaim.Authentication }));
        }

        _logger.Log(LogLevel.Warning, "Ignoring a plugin request not related to authentication.");

        return Task.FromResult(new GetOperationClaimsResponse(Array.Empty<OperationClaim>()));
    }
}

class SetLogLevelRequestHandler : RequestHandlerBase<SetLogLevelRequest, SetLogLevelResponse>
{
    public SetLogLevelRequestHandler(PluginLogger logger) : base(logger)
    {
    }

    public override Task<SetLogLevelResponse> HandleRequestAsync(SetLogLevelRequest request, CancellationToken cancellationToken)
    {
        _logger.LogLevel = request.LogLevel;
        // _logger.Log(LogLevel.Verbose, $"Setting log level to {request.LogLevel}.");
        return Task.FromResult(new SetLogLevelResponse(MessageResponseCode.Success));
    }
}

class GetAuthenticationCredentialsRequestHandler : RequestHandlerBase<GetAuthenticationCredentialsRequest, GetAuthenticationCredentialsResponse>
{
    public GetAuthenticationCredentialsRequestHandler(PluginLogger logger) : base(logger)
    {
    }

    public override async Task<GetAuthenticationCredentialsResponse> HandleRequestAsync(GetAuthenticationCredentialsRequest request, CancellationToken cancellationToken)
    {
        _logger.Log(LogLevel.Verbose, $"Beginning authentication credential request for package source '{request.Uri.AbsoluteUri}'.");
        var (success, message, token) = await GetTokenAsync(request);
        _logger.Log(success ? LogLevel.Minimal : LogLevel.Warning, message);

        if (!success)
        {
            return new GetAuthenticationCredentialsResponse(
                username: string.Empty,
                password: string.Empty,
                message,
                authenticationTypes: Array.Empty<string>(),
                MessageResponseCode.NotFound);
        }

        var response = new GetAuthenticationCredentialsResponse(
            username: "BEARER_TOKEN_USER",
            password: token,
            message,
            authenticationTypes: new[] { "Basic" },
            MessageResponseCode.Success);

        _logger.Log(
            LogLevel.Verbose,
            $"Returning successful credential response with username '{response.Username}' and " +
            $"authentication type {string.Join(", ", response.AuthenticationTypes)}.");

        return response;
    }

    private async Task<(bool Success, string Message, string? Token)> GetTokenAsync(GetAuthenticationCredentialsRequest request)
    {
        var tokenInfoJson = Environment.GetEnvironmentVariable("NUGET_TOKEN_INFO");
        if (string.IsNullOrWhiteSpace(tokenInfoJson))
        {
            return (Success: false, "Environment variable NUGET_TOKEN_INFO is not set.", Token: null);
        }

        TokenInfo? tokenInfo;
        try
        {
            tokenInfo = JsonConvert.DeserializeObject<TokenInfo>(tokenInfoJson);
            if (tokenInfo is null)
            {
                return (Success: false, "The NUGET_TOKEN_INFO environment variable is not set.", Token: null);
            }
        }
        catch (JsonException ex)
        {
            return (Success: false, "The NUGET_TOKEN_INFO environment variable could not be deserialized. " + ex.Message, Token: null);
        }

        if (tokenInfo.PackageSource != request.Uri.AbsoluteUri)
        {
            return (Success: false, $"The package source '{tokenInfo.PackageSource}' in NUGET_TOKEN_INFO " +
                $"does not match '{request.Uri.AbsoluteUri}' in the credential request.", Token: null);
        }

        _logger.Log(LogLevel.Verbose, "Found a matching package source in NUGET_TOKEN_INFO.");

        if (!Uri.TryCreate(tokenInfo.TokenUrl, UriKind.Absolute, out var tokenUrl))
        {
            return (Success: false, $"The token URL '{tokenInfo.TokenUrl}' in NUGET_TOKEN_INFO is not a valid URL.", Token: null);
        }

        _logger.Log(LogLevel.Verbose, $"Using audience value '{tokenInfo.Audience}' from NUGET_TOKEN_INFO.");
        var audience = $"audience={Uri.EscapeDataString(tokenInfo.Audience)}";
        var tokenUrlBuilder = new UriBuilder(tokenUrl);
        if (string.IsNullOrEmpty(tokenUrlBuilder.Query))
        {
            tokenUrlBuilder.Query = audience;
        }
        else
        {
            tokenUrlBuilder.Query += "&" + audience;
        }

        TokenResponse? tokenResponse;
        try
        {
            _logger.Log(LogLevel.Verbose, "Fetching a token from the token URL provided in NUGET_TOKEN_INFO.");
            var sw = Stopwatch.StartNew();
            using var httpClient = new HttpClient();
            using var requestMessage = new HttpRequestMessage(HttpMethod.Get, tokenUrlBuilder.Uri);
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenInfo.RuntimeToken);
            requestMessage.Headers.TryAddWithoutValidation("Accept", "application/json; api-version=2.0");
            using var responseMessage = await httpClient.SendAsync(requestMessage);
            _logger.Log(LogLevel.Verbose, $"Token URL returned HTTP {(int)responseMessage.StatusCode} after {sw.ElapsedMilliseconds}ms.");
            responseMessage.EnsureSuccessStatusCode();
            var tokenResponseJson = await responseMessage.Content.ReadAsStringAsync();
            tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(tokenResponseJson);
            if (string.IsNullOrEmpty(tokenResponse?.Value))
            {
                return (Success: false, "No token value was found in the token URL response.", Token: null);
            }
        }
        catch (Exception ex)
        {
            return (Success: false, $"Failed to fetch token from '{tokenInfo.TokenUrl}'. " + ex.Message, Token: null);
        }

        return (Success: true, "Successfully fetched a token using NUGET_TOKEN_INFO.", Token: tokenResponse.Value);
    }
}

class TokenInfo
{
    [JsonConstructor]
    public TokenInfo(string audience, string packageSource, string runtimeToken, string tokenUrl)
    {
        Audience = audience;
        PackageSource = packageSource;
        RuntimeToken = runtimeToken;
        TokenUrl = tokenUrl;
    }

    public string Audience { get; }
    public string PackageSource { get; }
    public string RuntimeToken { get; }
    public string TokenUrl { get; }
}

class TokenResponse
{
    [JsonConstructor]
    public TokenResponse(string value)
    {
        Value = value;
    }

    public string Value { get; }
}

class SetCredentialsRequestHandler : RequestHandlerBase<SetCredentialsRequest, SetCredentialsResponse>
{
    public SetCredentialsRequestHandler(PluginLogger logger) : base(logger)
    {
    }

    public override Task<SetCredentialsResponse> HandleRequestAsync(SetCredentialsRequest request, CancellationToken cancellationToken)
    {
        return Task.FromResult(new SetCredentialsResponse(MessageResponseCode.Success));
    }
}

abstract class RequestHandlerBase<TRequest, TResponse> : IRequestHandler
    where TResponse : class
{
    private static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
    {
        Converters = { new RedactingJsonConverter() }
    };
    protected readonly PluginLogger _logger;

    public RequestHandlerBase(PluginLogger logger)
    {
        _logger = logger;
    }

    public CancellationToken CancellationToken { get; }
    public abstract Task<TResponse> HandleRequestAsync(TRequest request, CancellationToken cancellationToken);

    public async Task HandleResponseAsync(IConnection connection, Message message, IResponseHandler responseHandler, CancellationToken cancellationToken)
    {
        _logger.Log(LogLevel.Debug, "Received request: " + JsonConvert.SerializeObject(message, Settings));
        var request = MessageUtilities.DeserializePayload<TRequest>(message);
        var response = await HandleRequestAsync(request, cancellationToken);
        _logger.Log(LogLevel.Debug, "Sending response: " + JsonConvert.SerializeObject(response, Settings));
        await _logger.PauseForEmptyAsync(TimeSpan.FromMilliseconds(500));
        await responseHandler.SendResponseAsync(message, response, cancellationToken);

        // Only start the logger after we know the log level. If we start sending log messages too early the
        // connection hangs.
        if (message.Method == MessageMethod.SetLogLevel)
        {
            _logger.Log(LogLevel.Debug, "Starting plugin logger.");
            _logger.Start();
        }
    }
}

class RedactingJsonConverter : JsonConverter
{
    public override bool CanConvert(Type objectType)
    {
        return objectType == typeof(GetAuthenticationCredentialsResponse);
    }

    public override object? ReadJson(JsonReader reader, Type objectType, object? existingValue, JsonSerializer serializer)
    {
        throw new NotSupportedException();
    }

    public override void WriteJson(JsonWriter writer, object? value, JsonSerializer serializer)
    {
        if (value is null)
        {
            writer.WriteNull();
            return;
        }

        var json = JToken.FromObject(value);
        json["Password"] = "REDACTED";
        serializer.Serialize(writer, json);
    }
}

class RequestHandlerCollection : ConcurrentDictionary<MessageMethod, IRequestHandler>, IRequestHandlers
{
    public void Add(MessageMethod method, IRequestHandler handler)
    {
        TryAdd(method, handler);
    }

    public void AddOrUpdate(MessageMethod method, Func<IRequestHandler> addHandlerFunc, Func<IRequestHandler, IRequestHandler> updateHandlerFunc)
    {
        AddOrUpdate(method, messageMethod => addHandlerFunc(), (messageMethod, requestHandler) => updateHandlerFunc(requestHandler));
    }

    public bool TryGet(MessageMethod method, out IRequestHandler? requestHandler)
    {
        return TryGetValue(method, out requestHandler);
    }

    public bool TryRemove(MessageMethod method)
    {
        return TryRemove(method, out _);
    }
}
