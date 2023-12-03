using NuGet.Protocol.Plugins;

namespace NuGet.Protocol.TokenCredentialProvider;

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
