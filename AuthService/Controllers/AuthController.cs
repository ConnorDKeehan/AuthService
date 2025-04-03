using AuthService.Interfaces;
using AuthService.Models.Requests;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthService.Controllers;

[ApiController]
[AllowAnonymous]
[Route("[controller]")]
public class AuthController(IAuthService authService) : ControllerBase
{
    [HttpPost("Register")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        await authService.RegisterAsync(request);

        return NoContent();
    }

    [HttpPost("Login")]
    public async Task<ActionResult<AccessTokenResponse>> Login([FromBody] LoginRequest request)
    {
        var result = await authService.LoginAsync(request);

        return Ok(result);
    }

    [HttpPost("RefreshAccessToken")]
    [Authorize]
    public async Task<ActionResult<AccessTokenResponse>> RefreshAccessToken([FromBody] string? pushNotificationToken)
    {
        var loginId = int.Parse(User.FindFirstValue("LoginId")!);
        var result = await authService.RefreshTokenAsync(loginId, pushNotificationToken);
        return Ok(result);
    }

    [HttpDelete("DeleteLogin")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DeleteLogin()
    {
        var loginId = int.Parse(User.FindFirstValue("LoginId")!);
        await authService.DeleteLoginAsync(loginId);

        return NoContent();
    }

    [HttpPost("LoginWithSocial")]
    public async Task<IActionResult> LoginWithSocial([FromBody] LoginWithSocialRequest request)
    {
        var token = await authService.LoginWithSocialAsync(request);
        return Ok(token);
    }
}
