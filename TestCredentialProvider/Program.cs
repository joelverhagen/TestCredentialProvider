using NuGet.Protocol.Plugins;
using System.Collections.Concurrent;
using static FileLogger;
using Newtonsoft.Json;

internal class Program
{
    private static async Task Main(string[] args)
    {
        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, _) =>
        {
            Log("Cancelled.");
            cts.Cancel();
        };


        if (args.Length == 1 && args[0] == "-Plugin")
        {
            var requestHandlers = new RequestHandlerCollection
            {
                { MessageMethod.Initialize, new InitializeRequestHandler() },
                { MessageMethod.GetOperationClaims, new GetOperationClaimsRequestHandler() },
                { MessageMethod.SetLogLevel, new SetLogLevelRequestHandler() },
                { MessageMethod.GetAuthenticationCredentials, new GetAuthenticationCredentialsRequestHandler() },
                { MessageMethod.SetCredentials, new SetCredentialsRequestHandler() },
            };

            using (var plugin = await PluginFactory.CreateFromCurrentProcessAsync(requestHandlers, ConnectionOptions.CreateDefault(), cts.Token))
            {
                var closedTaskCompletionSource = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                plugin.Closed += (_, _) =>
                {
                    Log("Closed.");
                    closedTaskCompletionSource.TrySetResult();
                };

                await closedTaskCompletionSource.Task;
            }
        }
    }
}

static class FileLogger
{
    public static void Log(string line)
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        File.AppendAllLines(Path.Combine(desktop, "TestCredentialProvider.log.txt"), new[] { line });
    }
}

class InitializeRequestHandler : RequestHandlerBase<InitializeRequest, InitializeResponse>
{
    public override Task<InitializeResponse> HandleRequestAsync(InitializeRequest request)
    {
        return Task.FromResult(new InitializeResponse(MessageResponseCode.Success));
    }
}

class GetOperationClaimsRequestHandler : RequestHandlerBase<GetOperationClaimsRequest, GetOperationClaimsResponse>
{
    public override Task<GetOperationClaimsResponse> HandleRequestAsync(GetOperationClaimsRequest request)
    {
        if (request.ServiceIndex is null && request.PackageSourceRepository is null)
        {
            return Task.FromResult(new GetOperationClaimsResponse(new[] { OperationClaim.Authentication }));
        }

        return Task.FromResult(new GetOperationClaimsResponse(Array.Empty<OperationClaim>()));
    }
}

class SetLogLevelRequestHandler : RequestHandlerBase<SetLogLevelRequest, SetLogLevelResponse>
{
    public override Task<SetLogLevelResponse> HandleRequestAsync(SetLogLevelRequest request)
    {
        return Task.FromResult(new SetLogLevelResponse(MessageResponseCode.Success));
    }
}

class GetAuthenticationCredentialsRequestHandler : RequestHandlerBase<GetAuthenticationCredentialsRequest, GetAuthenticationCredentialsResponse>
{
    public override Task<GetAuthenticationCredentialsResponse> HandleRequestAsync(GetAuthenticationCredentialsRequest request)
    {
        var response = new GetAuthenticationCredentialsResponse(
            "GitHubActions",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "Some message?",
            new[] { "Basic" },
            MessageResponseCode.Success);

        if (!response.IsValid())
        {
            throw new InvalidOperationException("Invalid response!");
        }

        return Task.FromResult(response);
    }
}

class SetCredentialsRequestHandler : RequestHandlerBase<SetCredentialsRequest, SetCredentialsResponse>
{
    public override Task<SetCredentialsResponse> HandleRequestAsync(SetCredentialsRequest request)
    {
        return Task.FromResult(new SetCredentialsResponse(MessageResponseCode.Success));
    }
}

abstract class RequestHandlerBase<TRequest, TResponse> : IRequestHandler
    where TResponse : class
{
    public CancellationToken CancellationToken { get; }

    public abstract Task<TResponse> HandleRequestAsync(TRequest request);

    public async Task HandleResponseAsync(IConnection connection, Message message, IResponseHandler responseHandler, CancellationToken cancellationToken)
    {
        var request = MessageUtilities.DeserializePayload<TRequest>(message);
        Log("Message: " + JsonConvert.SerializeObject(request));
        var response = await HandleRequestAsync(request);
        await responseHandler.SendResponseAsync(message, response, cancellationToken);
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
