using AuthService.Interfaces;
using AuthService.Models.Requests;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using AuthService.Extensions;
using AuthService.Models.Responses;
using System.IdentityModel.Tokens.Jwt;

namespace AuthService.Controllers;

[ApiController]
[AllowAnonymous]
[Route("[controller]")]
public class AuthController(IAuthService authService, IEmailService emailService) : ControllerBase
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
        var jwtToken = GetJwtSecurityTokenFromHeader();
        var loginId = int.Parse(jwtToken.Claims.FirstOrDefault(x => x.Type == "LoginId")!.Value);
        var deviceId = Guid.Parse(jwtToken.Claims.FirstOrDefault(c => c.Type == "DeviceId")!.Value);

        var result = await authService.RefreshTokensAsync(loginId, request.RefreshToken, request.PushNotificationToken, deviceId);
        return Ok(result);
    }

    [HttpPost("DeleteLogin")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> DeleteLogin([FromBody] string password)
    {
        var loginId = GetHttpLoginId();
        await authService.DeleteLoginAsync(loginId, password);

        return NoContent();
    }

    [HttpPost("SendForgotPasswordCode")]
    public async Task<ActionResult<int>> SendForgotPasswordCode([FromBody] SendForgotPasswordCodeRequest request)
    {
        var result = await authService.SendForgotPasswordCodeAsync(request);

        return Ok(result);
    }

    [HttpPost("SendVerifyEmailCode")]
    [Authorize]
    public async Task<ActionResult<int>> SendVerifyEmailCode()
    {
        var loginId = GetHttpLoginId();

        var result = await authService.SendVerifyEmailCodeAsync(loginId);

        return Ok(result);
    }

    [HttpPost("VerifyEmail")]
    [Authorize]
    public async Task<IActionResult> VerifyEmail(VerifyEmailRequest request)
    {
        var loginId = GetHttpLoginId();
        await authService.VerifyEmailAsync(loginId, request.code, request.twoFactorAuthCodeId);

        return NoContent();
    }

    [HttpPost("UpdatePasswordWithCode")]
    public async Task<IActionResult> UpdatePasswordWithCode([FromBody] UpdatePasswordWithCodeRequest request)
    {
        var result = await authService.UpdatePasswordWithCodeAsync(request);

        return Ok(result);
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
        var loginId = GetHttpLoginId();
        await authService.UpdateMetadataAsync(loginId, metadata);

        return NoContent();
    }

    private int GetHttpLoginId()
    {
        if (!int.TryParse(User.FindFirstValue("LoginId"), out int loginId))
        {
            throw new UnauthorizedAccessException("LoginId claim missing or invalid.");
        }

        return loginId;
    }

    private JwtSecurityToken GetJwtSecurityTokenFromHeader()
    {
        var authHeader = Request.Headers["Authorization"].FirstOrDefault();

        if (authHeader != null && authHeader.StartsWith("Bearer "))
        {
            var tokenStr = authHeader.Substring("Bearer ".Length).Trim();

            var handler = new JwtSecurityTokenHandler();
            if (handler.CanReadToken(tokenStr))
            {
                var token = handler.ReadJwtToken(tokenStr);
                return token;
            }
        }

        throw new UnauthorizedAccessException("Must still have an expired access token to refresh tokens");
    }
}
