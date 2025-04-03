namespace AuthService.Models.Requests;
public class RegisterRequest
{
    public required string Username { get; set; }
    public string? Email { get; set; }
    public required string Password { get; set; }
    public string? PushNotificationToken { get; set; }
    public string? SocialLoginIdentifier { get; set; }
    public string? Metadata { get; set; }
}
