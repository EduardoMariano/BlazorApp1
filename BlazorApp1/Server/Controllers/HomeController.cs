using Microsoft.AspNetCore.Mvc;

namespace BlazorApp1.Server.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
