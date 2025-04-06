using AuthService.Models.Entities;

namespace AuthService.Interfaces;

public interface IRefreshTokensRepository
{
    Task<RefreshToken?> GetRefreshTokenByHashAndLoginIdAsync(string hashedToken, int loginId);
    Task RevokeAllValidTokensByLoginIdAsync(int loginId);
    Task UpdateRefreshTokenByLoginAndDeviceAsync(string hashedToken, Guid deviceId, int loginId, int expiryTimeDays);
}