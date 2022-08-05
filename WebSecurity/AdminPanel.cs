using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebSecurity;

[Authorize]
public class AdminPanel : Controller
{
    //GET
   [HttpGet]
   [Authorize(Roles = "Administrators")]
    public IActionResult Index()
    {
        return View();
    }
}