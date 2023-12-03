using NuGet.Protocol.Plugins;

namespace NuGet.Protocol.TokenCredentialProvider;

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
