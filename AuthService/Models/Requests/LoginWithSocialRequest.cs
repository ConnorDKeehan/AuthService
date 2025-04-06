namespace AuthService.Models.Requests;

public record LoginWithSocialRequest(
    string Provider, 
    string IdToken, 
    string? PushNotificationToken
);