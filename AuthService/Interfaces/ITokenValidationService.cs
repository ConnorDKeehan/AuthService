using System.Security.Claims;

namespace AuthService.Interfaces;

public interface ITokenValidationService
{
    Task<bool> ValidateAsync(ClaimsPrincipal? principal);
}