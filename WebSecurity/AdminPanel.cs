using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebSecurity;

public class AdminPanel : Controller
{
    // GET
    [HttpGet]
    public IActionResult Index()
    {
        return View();
    }
}