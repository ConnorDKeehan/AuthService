using AuthService.Interfaces;
using System.Security.Claims;

namespace AuthService.Services;

public class TokenValidationService(ILoginsRepository loginsRepository) : ITokenValidationService
{
    public async Task<bool> ValidateAsync(ClaimsPrincipal? principal)
    {
        if (principal == null) {
            return false;
        }

        var loginId = int.Parse(principal.FindFirstValue("LoginId")!);
        var tokenVersion = int.Parse(principal.FindFirstValue("TokenVersion")!);

        var user = await loginsRepository.GetLoginByIdAsync(loginId);

        return user != null && user.TokenVersion == tokenVersion;
    }
}
