namespace AuthService.Models.Entities;

public class Login
{
    public int Id { get; set; }
    public required string Username { get; set; }
    public string? Email { get; set; }
    public required string Password { get; set; }
    public int TokenVersion { get; set; }
    public required bool Deleted { get; set; }
    public string? PushNotificationToken { get; set; }
    public string? SocialLoginIdentifier { get; set; }
    public DateTimeOffset DateCreated { get; set; }
    public string? Metadata { get; set; }
}
