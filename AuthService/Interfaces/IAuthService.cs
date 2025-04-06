using AuthService.Models.Entities;
using AuthService.Models.Requests;
using AuthService.Models.Responses;

namespace AuthService.Interfaces;

public interface IAuthService
{
    Task DeleteLoginAsync(int id);
    Task<TokenResponse> LoginAsync(LoginRequest request);
    Task<TokenResponse> LoginWithSocialAsync(LoginWithSocialRequest request);
    Task<TokenResponse> RefreshTokensAsync(int loginId, string refreshToken, string? pushNotificationToken, Guid deviceId);
    Task RegisterAsync(RegisterRequest request);
    Task UpdateMetadataAsync(int loginId, string metadata);
}