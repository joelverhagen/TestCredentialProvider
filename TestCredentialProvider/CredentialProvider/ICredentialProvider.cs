
namespace NuGet.Protocol.TokenCredentialProvider
{
    internal interface ICredentialProvider
    {
        Task<CredentialProviderResult> GetResponseOrNullAsync(string type, string tokenInfoJson);
    }
}