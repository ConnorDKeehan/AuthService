using AuthService.Contexts;
using AuthService.Interfaces;
using AuthService.Models.Entities;
using AuthService.Models.Enums;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Repositories;

public class TwoFactorAuthCodesRepository(AuthContext dbContext) : ITwoFactorAuthCodesRepository
{
    public async Task<int> AddTwoFactorAuthCodeAsync(int loginId, string hashedCode, TwoFactorAuthCodePurposesEnum purpose)
    {
        var twoFactorAuthCode = new TwoFactorAuthCode
        {
            LoginId = loginId,
            Code = hashedCode,
            Purpose = purpose.ToString(),
            DateCreatedUtc = DateTime.UtcNow,
            DateExpiryUtc = DateTime.UtcNow.AddMinutes(5),
            Revoked = false
        };

        await dbContext.TwoFactorAuthCodes.AddAsync(twoFactorAuthCode);

        await dbContext.SaveChangesAsync();

        return twoFactorAuthCode.Id;
    }

    public async Task<TwoFactorAuthCode?> GetValidTwoFactorAuthCodeAsync(int loginId, string hashedCode, TwoFactorAuthCodePurposesEnum purpose)
    {
        var result = await dbContext.TwoFactorAuthCodes.Where(x =>
            x.LoginId == loginId &&
            x.Code == hashedCode &&
            x.Purpose == purpose.ToString())
            .SingleAsync();

        return result;
    }

    public async Task<TwoFactorAuthCode> GetTwoFactorAuthCodeByIdAsync(int id)
    {
        var result = await dbContext.FindAsync<TwoFactorAuthCode>(id);

        if(result == null)
        {
            throw new KeyNotFoundException($"No TwoFactorAuthCode found with Id: {id}");
        }

        return result;
    }

    public async Task MarkTwoFactorAuthCodeAsUsedAsync(int id)
    {
        var result = await dbContext.FindAsync<TwoFactorAuthCode>(id);

        if (result == null)
        {
            throw new KeyNotFoundException($"No TwoFactorAuthCode found with Id: {id}");
        }

        result.DateUsedUtc = DateTime.UtcNow;
        result.Revoked = true;

        await dbContext.SaveChangesAsync();
    }
}
