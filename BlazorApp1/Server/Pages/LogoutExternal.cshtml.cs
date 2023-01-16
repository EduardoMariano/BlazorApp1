using BlazorApp1.Server.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net;

namespace BlazorApp1.Server.Pages
{
    public class LogoutExternalModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;        

        public LogoutExternalModel(SignInManager<ApplicationUser> signInManager)
        {
            _signInManager = signInManager;            
        }

        public IActionResult OnGetAsync(string returnUrl)
        {            
            _signInManager.SignOutAsync();
            if (returnUrl != null)
            {
                return LocalRedirect(returnUrl);
            }
            else
            {
                // This needs to be a redirect so that the browser performs a new
                // request and the identity for the user gets updated.
                return RedirectToPage();
            }
        }
    }
}
