using AuthService.Models.Entities;

namespace AuthService.Interfaces;

public interface ILoginsRepository
{
    Task AddLoginAsync(Login login);
    Task DeleteLoginAsync(int id);
    Task<bool> DoesThisUserAlreadyExistAsync(string username, string? email);
    Task<Login?> GetLoginByEmailAsync(string email);
    Task<Login> GetLoginByIdAsync(int id);
    Task<Login?> GetLoginBySocialIdentifierAsync(string socialIdentifier);
    Task<Login?> GetLoginByUsernameAsync(string username);
    Task UpdatePushNotificationTokenAsync(int loginId, string pushNotificationToken);
}