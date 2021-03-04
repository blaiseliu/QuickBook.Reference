using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using QuickBookReference.Core31.Models;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using Intuit.Ipp.Core;
using Intuit.Ipp.Data;
using Intuit.Ipp.OAuth2PlatformClient;
using Intuit.Ipp.QueryFilter;
using Intuit.Ipp.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace QuickBookReference.Core31.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        public static OAuth2Client auth2Client;

        public HomeController(ILogger<HomeController> logger, IConfiguration config)
        {
            _logger = logger;
            var clientId = config.GetValue<string>("QuickBook:ClientId");
            var clientSecret = config.GetValue<string>("QuickBook:ClientSecret");
            var redirectUrl = config.GetValue<string>("QuickBook:RedirectUrl");
            var environment = config.GetValue<string>("QuickBook:Environment");

            auth2Client = new OAuth2Client(clientId, clientSecret, redirectUrl, environment);
        }

        public IActionResult Index()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }


        public IActionResult InitiateAuth()
        {
            var scopes = new List<OidcScopes> { OidcScopes.Accounting };
            var authorizeUrl = auth2Client.GetAuthorizationURL(scopes);
            return Redirect(authorizeUrl);
        }
        [Authorize]
        public IActionResult Tokens()
        {
            return View(User.Claims);
        }
        public ActionResult ApiCallService()
        {
            if (HttpContext.Session.GetString("realmId") != null)
            {
                var realmId = HttpContext.Session.GetString("realmId");
                try
                {
                    var principal = User;
                    var oauthValidator = new OAuth2RequestValidator(principal.FindFirst("access_token").Value);

                    // Create a ServiceContext with Auth tokens and realmId
                    var serviceContext = new ServiceContext(realmId, IntuitServicesType.QBO, oauthValidator);
                    serviceContext.IppConfiguration.MinorVersion.Qbo = "23";

                    // Create a QuickBooks QueryService using ServiceContext
                    var querySvc = new QueryService<CompanyInfo>(serviceContext);
                    var companyInfo = querySvc.ExecuteIdsQuery("SELECT * FROM CompanyInfo").FirstOrDefault();

                    var output = "Company Name: " + companyInfo?.CompanyName + " Company Address: " + 
                                 companyInfo?.CompanyAddr.Line1 + ", " + 
                                 companyInfo?.CompanyAddr.City + ", " + 
                                 companyInfo?.CompanyAddr.Country + " " + 
                                 companyInfo?.CompanyAddr.PostalCode;
                    return View("ApiCallService", "QBO API call Successful!! Response: " + output);
                }
                catch (Exception ex)
                {
                    return View("ApiCallService", "QBO API call Failed!" + " Error message: " + ex.Message);
                }
            }
            else
            {
                return View("ApiCallService", "QBO API call Failed!");
            }
        }
    }
}
