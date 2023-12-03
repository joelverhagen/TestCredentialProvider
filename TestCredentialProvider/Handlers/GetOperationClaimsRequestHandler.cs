using NuGet.Common;
using NuGet.Protocol.Plugins;

namespace NuGet.Protocol.TokenCredentialProvider;

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
