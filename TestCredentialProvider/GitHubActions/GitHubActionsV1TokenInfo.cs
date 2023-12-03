using Newtonsoft.Json;

namespace NuGet.Protocol.TokenCredentialProvider;

class GitHubActionsV1TokenInfo : TokenInfo
{
    [JsonConstructor]
    public GitHubActionsV1TokenInfo(string type, string packageSource, string audience, string runtimeToken, string tokenUrl)
        : base(type, packageSource)
    {
        Audience = audience;
        RuntimeToken = runtimeToken;
        TokenUrl = tokenUrl;
    }

    public string Audience { get; }
    public string RuntimeToken { get; }
    public string TokenUrl { get; }
}