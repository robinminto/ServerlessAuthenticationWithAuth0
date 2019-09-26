using System;
using System.IO;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace ServerlessAuthenticationWithAuth0
{
    public static class GreetingsEngine
    {
        private const string Header_Authorization = "Authorization";

        [FunctionName("Greeting")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            ClaimsPrincipal principal;

            AuthenticationHeaderValue authorization = null;
            if (req.Headers.ContainsKey(Header_Authorization))
            {
                AuthenticationHeaderValue.TryParse(req.Headers[Header_Authorization], out authorization);
            }

            if (authorization == null || 
                !string.Equals(authorization.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase) || 
                (principal = await Security.ValidateTokenAsync(authorization.Parameter, log)) == null)
            {
                return new UnauthorizedResult();
            }

            string name = req.Query["name"];

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;

            return name != null
                ? (ActionResult)new OkObjectResult(new GreetingResponse
                    { Greeting = $"Hello, {name}", AuthenticationType = "Auth0" })
                : new BadRequestObjectResult("Please pass a name on the query string or in the request body");
        }
    }
}
