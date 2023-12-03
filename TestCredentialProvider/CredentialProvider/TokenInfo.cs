using Newtonsoft.Json;

namespace NuGet.Protocol.TokenCredentialProvider;

class TokenInfo
{
    [JsonConstructor]
    public TokenInfo(string type, string packageSource)
    {
        Type = type;
        PackageSource = packageSource;
    }

    public string Type { get; }
    public string PackageSource { get; }
}
