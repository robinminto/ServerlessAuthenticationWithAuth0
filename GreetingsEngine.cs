using System.IO;
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
        [FunctionName("Greeting")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            ClaimsPrincipal principal;

            // This is a hack. I'm not clear why req.HttpContext.GetTokenAsync(JwtBearerDefaults.AuthenticationScheme... isn't working.
            var bearerToken = req.HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            if ((principal = await Security.ValidateTokenAsync(bearerToken, log)) == null)
            {
                return new UnauthorizedResult();
            }

            string name = req.Query["name"];

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;

            return name != null
                ? (ActionResult)new OkObjectResult(new GreetingResponse
                    { Greeting = $"Hello, {name}", AuthenticationType = "Auth0", PrincipalName = principal.Identity.Name })
                : new BadRequestObjectResult("Please pass a name on the query string or in the request body");
        }
    }
}
