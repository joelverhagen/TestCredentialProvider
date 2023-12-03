namespace NuGet.Protocol.TokenCredentialProvider;

class CredentialProviderResult
{
    private CredentialProviderResult()
    {
    }

    public CredentialProviderResultType Type { get; private init; }
    public string? ErrorMessage { get; private init; }
    public string? SuccessMessage { get; private init; }
    public string? BearerToken { get; private init; }

    public static CredentialProviderResult NotSupported()
    {
        return new CredentialProviderResult
        {
            Type = CredentialProviderResultType.NotSupported,
        };
    }

    public static CredentialProviderResult Error(string errorMessage)
    {
        return new CredentialProviderResult
        {
            Type = CredentialProviderResultType.Error,
            ErrorMessage = errorMessage,
        };
    }

    public static CredentialProviderResult BearerTokenResult(string bearerToken, string successMessage)
    {
        return new CredentialProviderResult
        {
            Type = CredentialProviderResultType.BearerToken,
            BearerToken = bearerToken,
            SuccessMessage = successMessage,
        };
    }
}
