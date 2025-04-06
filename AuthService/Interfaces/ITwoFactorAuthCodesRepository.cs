using AuthService.Models.Entities;
using AuthService.Models.Enums;

namespace AuthService.Interfaces;

public interface ITwoFactorAuthCodesRepository
{
    Task<int> AddTwoFactorAuthCodeAsync(int loginId, string hashedCode, TwoFactorAuthCodePurposesEnum purpose);
    Task<TwoFactorAuthCode> GetTwoFactorAuthCodeByIdAsync(int id);
    Task<TwoFactorAuthCode?> GetValidTwoFactorAuthCodeAsync(int loginId, string hashedCode, TwoFactorAuthCodePurposesEnum purpose);
    Task MarkTwoFactorAuthCodeAsUsedAsync(int id);
}