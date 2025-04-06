using AuthService.Interfaces;
using AuthService.Models.Requests;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using AuthService.Extensions;
using AuthService.Models.Responses;

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
    public async Task<ActionResult<TokenResponse>> Login([FromBody] LoginRequest request)
    {
        var result = await authService.LoginAsync(request);

        return Ok(result);
    }

    [HttpPost("RefreshTokens")]
    public async Task<ActionResult<TokenResponse>> RefreshTokens([FromBody] RefreshTokensRequest request)
    {
        var loginId = int.Parse(User.FindFirstValue("LoginId")!);
        Guid deviceId = User.FindFirstValue("DeviceId")?.TryParseGuid() ?? Guid.NewGuid();
        var result = await authService.RefreshTokensAsync(loginId, request.RefreshToken, request.PushNotificationToken, deviceId);
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
    public async Task<ActionResult<TokenResponse>> LoginWithSocial([FromBody] LoginWithSocialRequest request)
    {
        var token = await authService.LoginWithSocialAsync(request);
        return Ok(token);
    }

    [HttpPost("UpdateMetadata")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> UpdateMetadata([FromBody] string metadata)
    {
        var loginId = int.Parse(User.FindFirstValue("LoginId")!);
        await authService.UpdateMetadataAsync(loginId, metadata);

        return NoContent();
    }
}
