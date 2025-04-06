using AuthService.Models.Entities;
using AuthService.Models.Requests;
using AuthService.Models.Responses;

namespace AuthService.Interfaces;

public interface IAuthService
{
    Task DeleteLoginAsync(int id, string password);
    Task<TokenResponse> LoginAsync(LoginRequest request);
    Task<TokenResponse> LoginWithSocialAsync(LoginWithSocialRequest request);
    Task<TokenResponse> RefreshTokensAsync(int loginId, string refreshToken, string? pushNotificationToken, Guid deviceId);
    Task RegisterAsync(RegisterRequest request);
    Task<int> SendForgotPasswordCodeAsync(SendForgotPasswordCodeRequest request);
    Task<int> SendVerifyEmailCodeAsync(int loginId);
    Task UpdateMetadataAsync(int loginId, string metadata);
    Task<TokenResponse> UpdatePasswordWithCodeAsync(UpdatePasswordWithCodeRequest request);
    Task<TokenResponse> UpdatePasswordWithPasswordAsync(int loginId, UpdatePasswordWithPasswordRequest updatePasswordRequest, Guid deviceId);
    Task VerifyEmailAsync(int loginId, string code, int twoFactorAuthCodeId);
}