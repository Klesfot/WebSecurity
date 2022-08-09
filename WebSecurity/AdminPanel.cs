using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebSecurity;

[Authorize(Roles = "Administrators")]
public class AdminPanel : Controller
{
    //GET
    [HttpGet]
    public IActionResult Index()
    {
        return View();
    }
}