using AuthService.Contexts;
using AuthService.Interfaces;
using AuthService.Models.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Repositories;

public class RefreshTokensRepository(AuthContext dbContext) : IRefreshTokensRepository
{
    public async Task<RefreshToken?> GetRefreshTokenByHashAndLoginIdAsync(string hashedToken, int loginId)
    {
        var result = await dbContext.RefreshTokens.Where(x => x.Token == hashedToken && x.LoginId == loginId).SingleOrDefaultAsync();

        return result;
    }

    public async Task UpdateRefreshTokenByLoginAndDevice(string hashedToken, Guid deviceId, int loginId, int expiryTimeDays) 
    {
        using var transaction = await dbContext.Database.BeginTransactionAsync();

        await dbContext.RefreshTokens
            .Where(x => x.LoginId == loginId && x.DeviceId == deviceId && !x.Revoked)
            .ExecuteUpdateAsync(set => set.SetProperty(t => t.Revoked, true));

        await dbContext.RefreshTokens.AddAsync(new RefreshToken
        {
            LoginId = loginId,
            Token = hashedToken,
            DeviceId = deviceId,
            DateCreatedUtc = DateTime.UtcNow,
            DateExpiryUtc = DateTime.UtcNow.AddDays(expiryTimeDays),
            Revoked = false
        });

        await dbContext.SaveChangesAsync();
        await transaction.CommitAsync();
    }
}
