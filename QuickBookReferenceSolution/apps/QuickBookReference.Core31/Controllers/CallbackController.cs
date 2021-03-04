using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace QuickBookReference.Core31.Controllers
{
    public class CallbackController:Controller
    {
        private readonly ILogger<CallbackController> _logger;

        public CallbackController(ILogger<CallbackController> logger)
        {
            _logger = logger;
        }
        public async Task<IActionResult> Index()
        {
            
            string state = Request.Query["state"];
            string code = Request.Query["code"];
            string realmId = Request.Query["realmId"];

            var isValidState = state.Equals(HomeController.auth2Client.CSRFToken, StringComparison.Ordinal);

            ViewBag.State = $"{state} ({(isValidState?"valid":"invalid")})";

            //string code = queryDictionary["code"].ToString() ?? "none";
            //string realmId = queryDictionary["realmId"].ToString() ?? "none";
            await GetAuthTokensAsync(code, realmId);

            //ViewBag.Error = queryDictionary["error"].ToString() ?? "none";

            return RedirectToAction("Tokens", "Home");
        }

        private async Task GetAuthTokensAsync(string code, string realmId)
        {
            //if (realmId != null)
            //{
            //    HttpContext.Session.SetString("realmId", realmId);
            //}

            var tokenResponse = await HomeController.auth2Client.GetBearerTokenAsync(code);

            var claims = new List<Claim>();

            claims.Add(new Claim("realmId", realmId));
            //if (HttpContext.Session.GetString("realmId") != null)
            //{
            //    claims.Add(new Claim("realmId", HttpContext.Session.GetString("realmId")));
            //}

            if (!string.IsNullOrWhiteSpace(tokenResponse.AccessToken))
            {
                claims.Add(new Claim("access_token", tokenResponse.AccessToken));
                claims.Add(new Claim("access_token_expires_at", (DateTime.Now.AddSeconds(tokenResponse.AccessTokenExpiresIn)).ToString()));
            }

            if (!string.IsNullOrWhiteSpace(tokenResponse.RefreshToken))
            {
                claims.Add(new Claim("refresh_token", tokenResponse.RefreshToken));
                claims.Add(new Claim("refresh_token_expires_at", (DateTime.Now.AddSeconds(tokenResponse.RefreshTokenExpiresIn)).ToString()));
            }
            var claimsIdentity = new ClaimsIdentity(claims, "Cookies");
            await
                HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity));
        }
    }
}
