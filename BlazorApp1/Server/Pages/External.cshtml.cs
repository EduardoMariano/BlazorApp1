using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Security.Claims;
using BlazorApp1.Server.Extensions;
using BlazorApp1.Server.Models;
using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BlazorApp1.Server.Pages
{
    [AllowAnonymous]
    [IgnoreAntiforgeryToken]
    public class ExternalModel : PageModel
    {
        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }
        }

        private readonly SignInManager<ApplicationUser> _signInManager;
        [TempData] public string ErrorMessage { get; set; }
        public string ProviderDisplayName { get; set; }
        public string ReturnUrl { get; set; }
        [BindProperty] public InputModel Input { get; set; }

        public ExternalModel(
            SignInManager<ApplicationUser> signInManager)
        {
            _signInManager = signInManager;
        }

        public IActionResult OnGetAsync(string returnurl, string schema)
        {
            returnurl = (returnurl == null) ? "/" : returnurl;
            returnurl = (!returnurl.StartsWith("/")) ? "/" + returnurl : returnurl;

            var providertype = schema;
            if (providertype != "")
            {
                var sh = returnurl + (returnurl.Contains("?") ? "&" : "?") + "reload=post";
                var redirectUrl = Url.Page("./External", pageHandler: "Callback", values: new { sh });
                var properties = _signInManager.ConfigureExternalAuthenticationProperties(providertype, redirectUrl);
                return new ChallengeResult(providertype, properties);
                //return new ChallengeResult(providertype, new AuthenticationProperties { RedirectUri = returnurl + (returnurl.Contains("?") ? "&" : "?") + "reload=post" });
            }
            else
            {
                HttpContext.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                return new EmptyResult();
            }
        }
        public async Task<IActionResult> OnGetCallbackAsync(string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            if (remoteError != null)
            {
                ErrorMessage = $"Error from external provider: {remoteError}";
                return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                ErrorMessage = "Error loading external login information.";
                return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                return LocalRedirect(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return RedirectToPage("./Lockout");
            }
            else
            {
                // If the user does not have an account, then ask the user to create an account.
                ReturnUrl = returnUrl;
                ProviderDisplayName = info.ProviderDisplayName;
                if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
                {
                    Input = new InputModel
                    {
                        Email = info.Principal.FindFirstValue(ClaimTypes.Email)
                    };
                }
                return Page();
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
