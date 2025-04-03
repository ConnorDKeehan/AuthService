using AuthService.Models.Entities;
using AuthService.Models.Requests;

namespace AuthService.Interfaces;

public interface IAuthService
{
    Task DeleteLoginAsync(int id);
    Task<string> LoginAsync(LoginRequest request);
    Task<string> LoginWithSocialAsync(LoginWithSocialRequest request);
    Task<string> RefreshTokenAsync(int loginId, string? pushNotificationToken);
    Task RegisterAsync(RegisterRequest request);
}