using NuGet.Protocol.Plugins;

namespace NuGet.Protocol.TokenCredentialProvider;

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
