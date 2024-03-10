using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Mvc;
using ServerLibrary.Repositories.Contracts;

namespace Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IUserAccount accountInterface) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IActionResult> CreateAccount(Register user) 
        {
            if (user == null) return BadRequest("Model is empty");
            var result = await accountInterface.CreateAsync(user);
            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(Login user)
        {
            if (user == null) return BadRequest("Model is empty");
            var result = await accountInterface.SignInAsync(user);
            return Ok(result);
        }

    }
}
