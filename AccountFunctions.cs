using System;
using System.IO;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace ServerlessAuthenticationWithAuth0
{
    public static class AccountFunctions
    {
        private const string Header_Authorization = "Authorization";
        private const string AuthenticationType = "Auth0";
        private static decimal _balance = 0;

        [FunctionName("Balance")]
        public static async Task<IActionResult> Balance(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)]
            HttpRequest req,
            ILogger log)
        {
            log.LogInformation("Getting account balance.");

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

            return (ActionResult) new OkObjectResult(new BalanceResponse
                {Balance = _balance, AuthenticationType = AuthenticationType});
        }

        [FunctionName("Credit")]
        public static async Task<IActionResult> Credit(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)]
            HttpRequest req,
            ILogger log)
        {
            log.LogInformation("Crediting account.");

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

            return await CreditOrDebit(req, true);
        }

        [FunctionName("Debit")]
        public static async Task<IActionResult> Debit(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)]
            HttpRequest req,
            ILogger log)
        {
            log.LogInformation("Debiting account.");

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

            return await CreditOrDebit(req, false);
        }

        private static async Task<IActionResult> CreditOrDebit(HttpRequest req, bool credit)
        {
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);

            if (data?.Amount == null)
            {
                return new BadRequestObjectResult("Please pass an amount in the request body");
            }

            decimal amount = (decimal) data?.Amount;
            if (credit)
            {
                _balance += amount;
            }
            else
            {
                _balance -= amount;
            }

            return new OkObjectResult(new CreditOrDebitResponse
                {Amount = amount, AuthenticationType = AuthenticationType}
            );
        }
    }
}