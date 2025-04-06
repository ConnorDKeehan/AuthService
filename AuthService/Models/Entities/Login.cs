namespace AuthService.Models.Entities;

public class Login
{
    public int Id { get; set; }
    public required string Username { get; set; }
    public string? Email { get; set; }
    public bool EmailVerified { get; set; }
    public required string Password { get; set; }
    public int AccessTokenVersion { get; set; }
    public required bool Deleted { get; set; }
    public string? PushNotificationToken { get; set; }
    public string? SocialLoginIdentifier { get; set; }
    public DateTime DateCreatedUtc { get; set; }
    public string? Metadata { get; set; }
}
