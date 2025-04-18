﻿using AuthService.Contexts;
using AuthService.Interfaces;
using AuthService.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Repositories;

public class LoginsRepository(AuthContext dbContext, IRefreshTokensRepository refreshTokensRepository) : ILoginsRepository
{
    public async Task<bool> DoesThisUserAlreadyExistAsync(string username, string? email)
    {
        bool result = await dbContext.Logins.AnyAsync(u => u.Username == username || (u.Email == email && !string.IsNullOrEmpty(u.Email)));

        return result;
    }

    public async Task AddLoginAsync(Login login)
    {
        dbContext.Logins.Add(login);
        await dbContext.SaveChangesAsync();
    }

    public async Task<Login?> GetLoginByUsernameAsync(string username)
    {
        var login = await dbContext.Logins.Where(u => u.Username == username && u.Deleted == false).SingleOrDefaultAsync();

        return login;
    }

    public async Task<Login?> GetLoginByEmailAsync(string email)
    {
        var login = await dbContext.Logins.Where(u => u.Email == email && u.Deleted == false).SingleOrDefaultAsync();

        return login;
    }

    public async Task<Login?> GetLoginBySocialIdentifierAsync(string socialIdentifier)
    {
        var login = await dbContext.Logins.Where(u => u.SocialLoginIdentifier == socialIdentifier && u.Deleted == false).SingleOrDefaultAsync();

        return login;
    }

    public async Task<Login> GetLoginByIdAsync(int id)
    {
        var login = await dbContext.Logins.Where(x => x.Id == id && x.Deleted == false).SingleOrDefaultAsync();

        if(login == null)
        {
            throw new KeyNotFoundException($"No Login Found with Id: {id}");
        }

        return login;
    }

    public async Task DeleteLoginAsync(int id)
    {
        using var transaction = await dbContext.Database.BeginTransactionAsync();
        var login = await dbContext.FindAsync<Login>(id);

        if(login == null)
        {
            throw new KeyNotFoundException($"LoginId: {id} not found");
        }

        login.Deleted = true;

        //This invalidates all current access tokens
        login.AccessTokenVersion++;

        await refreshTokensRepository.RevokeAllValidTokensByLoginIdAsync(id);

        await dbContext.SaveChangesAsync();
        await transaction.CommitAsync();
    }

    public async Task UpdatePushNotificationTokenAsync(int loginId, string pushNotificationToken)
    {
        var login = await dbContext.Logins.Where(x => x.Id == loginId).SingleAsync();

        login.PushNotificationToken = pushNotificationToken;

        await dbContext.SaveChangesAsync();
    }

    public async Task UpdateMetadataAsync(int loginId, string metadata)
    {
        var login = await dbContext.FindAsync<Login>(loginId);

        if(login == null)
        {
            throw new KeyNotFoundException($"LoginId: {loginId} not found");
        }

        login.Metadata = metadata;
        await dbContext.SaveChangesAsync();
    }

    public async Task UpdatePasswordAsync(int loginId, string newHashedPassword)
    {
        using var transaction = await dbContext.Database.BeginTransactionAsync();
        var login = await dbContext.FindAsync<Login>(loginId);

        if (login == null)
        {
            throw new KeyNotFoundException($"LoginId: {loginId} not found");
        }

        login.AccessTokenVersion++;
        await refreshTokensRepository.RevokeAllValidTokensByLoginIdAsync(loginId);

        await dbContext.SaveChangesAsync();
        await transaction.CommitAsync();
    }

    public async Task MarkEmailAsVerifiedAsync(int loginId)
    {
        var login = await dbContext.FindAsync<Login>(loginId);

        if (login == null)
        {
            throw new KeyNotFoundException($"LoginId: {loginId} not found");
        }

        login.EmailVerified = true;
    }
}
