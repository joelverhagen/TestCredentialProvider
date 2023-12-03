using System.Diagnostics;
using System.Net.Http.Headers;
using Newtonsoft.Json;
using NuGet.Common;

namespace NuGet.Protocol.TokenCredentialProvider;

class GitHubActionsCredentialProvider : ICredentialProvider
{
    private readonly PluginLogger _logger;

    public GitHubActionsCredentialProvider(PluginLogger logger)
    {
        _logger = logger;
    }

    public async Task<CredentialProviderResult> GetResponseOrNullAsync(string type, string tokenInfoJson)
    {
        if (type != "GitHubActionsV1")
        {
            return CredentialProviderResult.NotSupported();
        }

        GitHubActionsV1TokenInfo? tokenInfo;
        try
        {
            tokenInfo = JsonConvert.DeserializeObject<GitHubActionsV1TokenInfo>(tokenInfoJson)!;
        }
        catch (JsonException ex)
        {
            return CredentialProviderResult.Error("Failed to read GitHub Actions NUGET_TOKEN_INFO. " + ex.Message);
        }

        if (!Uri.TryCreate(tokenInfo.TokenUrl, UriKind.Absolute, out var tokenUrl)
            || tokenUrl.Scheme != "https")
        {
            return CredentialProviderResult.Error($"The token URL '{tokenInfo.TokenUrl}' in NUGET_TOKEN_INFO is not a valid HTTPS URL.");
        }

        _logger.Log(LogLevel.Debug, $"Using audience value '{tokenInfo.Audience}' from NUGET_TOKEN_INFO.");
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

        GitHubActionsTokenResponse? tokenResponse;
        try
        {
            _logger.Log(LogLevel.Debug, "Fetching a token from the token URL provided in NUGET_TOKEN_INFO.");
            var sw = Stopwatch.StartNew();
            using var httpClient = new HttpClient();
            using var requestMessage = new HttpRequestMessage(HttpMethod.Get, tokenUrlBuilder.Uri);
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenInfo.RuntimeToken);
            requestMessage.Headers.TryAddWithoutValidation("Accept", "application/json; api-version=2.0");
            using var responseMessage = await httpClient.SendAsync(requestMessage);
            _logger.Log(LogLevel.Debug, $"Token URL returned HTTP {(int)responseMessage.StatusCode} after {sw.ElapsedMilliseconds}ms.");
            responseMessage.EnsureSuccessStatusCode();
            var tokenResponseJson = await responseMessage.Content.ReadAsStringAsync();
            tokenResponse = JsonConvert.DeserializeObject<GitHubActionsTokenResponse>(tokenResponseJson);
            if (string.IsNullOrEmpty(tokenResponse?.Value))
            {
                return CredentialProviderResult.Error("No token value was found in the token URL response.");
            }
        }
        catch (Exception ex)
        {
            return CredentialProviderResult.Error($"Failed to fetch token from '{tokenInfo.TokenUrl}'. " + ex.Message);
        }

        return CredentialProviderResult.BearerTokenResult(tokenResponse.Value, "Successfully fetched a GitHub Actions token.");
    }
}
