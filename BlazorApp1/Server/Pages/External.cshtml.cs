using System.Net;
using BlazorApp1.Server.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BlazorApp1.Server.Pages
{
    [AllowAnonymous]
    [IgnoreAntiforgeryToken]
    public class ExternalModel : PageModel
    {
        public IActionResult OnGetAsync(string returnurl)
        {
            returnurl = (returnurl == null) ? "/" : returnurl;
            returnurl = (!returnurl.StartsWith("/")) ? "/" + returnurl : returnurl;

            var providertype = "oidc-idserver";
            if (providertype != "")
            {
                var sh = returnurl + (returnurl.Contains("?") ? "&" : "?") + "reload=post";
                return new ChallengeResult(providertype, new AuthenticationProperties { RedirectUri = returnurl + (returnurl.Contains("?") ? "&" : "?") + "reload=post" });
            }
            else
            {
                HttpContext.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                return new EmptyResult();
            }
        }

        public IActionResult OnPostAsync(string returnurl)
        {
            if (returnurl == null)
            {
                returnurl = "";
            }
            if (!returnurl.StartsWith("/"))
            {
                returnurl = "/" + returnurl;
            }

            // remove reload parameter
            returnurl = returnurl.ReplaceMultiple(new string[] { "?reload=post", "&reload=post" }, "");

            return LocalRedirect(Url.Content("~" + returnurl));
        }


    }
}
