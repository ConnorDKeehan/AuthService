namespace AuthService.Models.Requests;

public record RegisterRequest(
    string Username,
    string? Email,
    string Password,
    string? PushNotificationToken,
    string? SocialLoginIdentifier,
    string? Metadata
);