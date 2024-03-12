using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Mvc;
using ServerLibrary.Repositories.Contracts;

namespace Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IUserAccount accountInterface) : ControllerBase
    {
        private const string BAD_REQUEST_MESSAGE = "Model is empty";

        [HttpPost("register")]
        public async Task<IActionResult> CreateAsync(Register user) 
        {
            if (user == null) return BadRequest(BAD_REQUEST_MESSAGE);
            var result = await accountInterface.CreateAsync(user);
            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> SignInAsync(Login user)
        {
            if (user == null) return BadRequest(BAD_REQUEST_MESSAGE);
            var result = await accountInterface.SignInAsync(user);
            return Ok(result);
        }
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshTokenAsync(RefreshToken token)
        {
            if (token == null) return BadRequest(BAD_REQUEST_MESSAGE);
            var result = await accountInterface.RefreshTokenAsync(token);
            return Ok(result);
        }

    }
}
