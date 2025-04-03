namespace AuthService.Models.Requests;

public class LoginWithSocialRequest
{
    public required string Provider { get; set; }
    public required string IdToken { get; set; }
    public string? PushNotificationToken { get; set; }
}
