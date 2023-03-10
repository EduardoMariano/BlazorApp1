using BlazorApp1.Server.Extensions;
using BlazorApp1.Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Security.Claims;
using System.Text;

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
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserStore<ApplicationUser> _userStore;
        private readonly IUserEmailStore<ApplicationUser> _emailStore;
        
        [TempData] public string ErrorMessage { get; set; }
        public string ProviderDisplayName { get; set; }
        public string ReturnUrl { get; set; }
        [BindProperty] public InputModel Input { get; set; }

        public ExternalModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IUserStore<ApplicationUser> userStore)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = GetEmailStore(); 
            
        }

        public IActionResult OnGetAsync(string returnUrl, string schema)
        {
            returnUrl = (returnUrl == null) ? "/" : returnUrl;
            returnUrl = (!returnUrl.StartsWith("/")) ? "/" + returnUrl : returnUrl;

            if (schema == "oidc")
                returnUrl = "/fetchdata";
            else
                returnUrl = "/counter";
            if (schema != "")
            {                
                var redirectUrl = Url.Page("./External", pageHandler: "Callback", values: new { returnUrl });
                var properties = _signInManager.ConfigureExternalAuthenticationProperties(schema, redirectUrl);
                return new ChallengeResult(schema, properties);                
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
                List<Claim> claims = new List<Claim>();
                var user = await _signInManager.UserManager.FindByNameAsync(info.Principal.FindFirstValue(ClaimTypes.Email));
                if (info.LoginProvider == "oidc")
                    claims.Add(new Claim("IsUserAdmin", "true"));                 
                claims.Add(new Claim("AvailableButtonCounter", "true"));                
                await _signInManager.UserManager.AddClaimsAsync(user, claims);
                return LocalRedirect(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return RedirectToPage("./Lockout");
            }
            else
            {
                Input = new InputModel
                    {
                        Email = info.Principal.FindFirstValue(ClaimTypes.Email)
                    };
                var user = CreateUser();
                await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
                await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);

                var userResult = await _userManager.CreateAsync(user);
                if (userResult.Succeeded)
                {                    
                    IdentityResult roleResult;
                    if (info.LoginProvider == "oidc")
                        roleResult = await _userManager.AddToRoleAsync(user, "Admin");
                    else
                        roleResult = await _userManager.AddToRoleAsync(user, "Vendor");
                    var roleUser = await _userManager.AddToRoleAsync(user, "User");
                    var res = await _userManager.AddLoginAsync(user, info);
                    if (res.Succeeded && roleResult.Succeeded && roleUser.Succeeded)
                    {                      

                        var userId = await _userManager.GetUserIdAsync(user);
                        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                        code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
                        var results = await _userManager.ConfirmEmailAsync(user, code);                        
                        if (results.Succeeded)
                        {
                            List<Claim> claims = new List<Claim>();                            
                            if (info.LoginProvider == "oidc")
                                claims.Add(new Claim("IsUserAdmin", "true"));
                            claims.Add(new Claim("AvailableButtonCounter", "true"));                            
                            await _signInManager.UserManager.AddClaimsAsync(user, claims);                            
                            await _signInManager.SignInAsync(user, isPersistent: false, info.LoginProvider);
                            return LocalRedirect(returnUrl);
                        }
                        
                    }
                    ErrorMessage = "Error loading external login information. Internal error server";
                    return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
                }
                else
                {
                    ErrorMessage = "Error loading external login information. Internal error server";
                    return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
                }
            }
        }

        private ApplicationUser CreateUser()
        {
            try
            {
                return Activator.CreateInstance<ApplicationUser>();
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(ApplicationUser)}'. " +
                    $"Ensure that '{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the external login page in /Areas/Identity/Pages/Account/ExternalLogin.cshtml");
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

        private IUserEmailStore<ApplicationUser> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
            {
                throw new NotSupportedException("The default UI requires a user store with email support.");
            }
            return (IUserEmailStore<ApplicationUser>)_userStore;
        }        
    }
}
