using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace TestServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class V3Controller : ControllerBase
    {
        private readonly ILogger<V3Controller> _logger;

        public V3Controller(ILogger<V3Controller> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Route("/api/v3/index.json")]
        public ActionResult Index()
        {
            return new ObjectResult(new V3ServiceIndex
            {
                Resources =
                {
                    new V3ServiceIndexResource("PackageBaseAddress/3.0.0", Url.Action(nameof(PackageContent), controller: null, values: null, protocol: "http")! + "/"),
                }
            });;
        }

        [HttpGet]
        [Route("/api/v3/package-content/{**content}")]
        public ActionResult PackageContent(string? content)
        {
            _logger.LogWarning("Authorization: {Header}", Request.Headers.Authorization.ToString());

            Response.StatusCode = 401;
            Response.Headers[HeaderNames.WWWAuthenticate] = "Basic realm=\"example\"";
            return new ObjectResult(new { Success = false, Content = content, Message = "Access denied." });
        }
    }

    public class V3ServiceIndex
    {
        [JsonPropertyName("version")]
        public string Version { get; set; } = "3.0.0";

        [JsonPropertyName("resources")]
        public List<V3ServiceIndexResource> Resources { get; set; } = new List<V3ServiceIndexResource>();
    }

    public class V3ServiceIndexResource
    {
        public V3ServiceIndexResource(string type, string id)
        {
            Type = type;
            Id = id;
        }

        [JsonPropertyName("@type")]
        public string Type { get; set; }

        [JsonPropertyName("@id")]
        public string Id { get; set; }

    }
}
