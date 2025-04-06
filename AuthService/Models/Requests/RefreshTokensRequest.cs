namespace AuthService.Models.Requests;

public record RefreshTokensRequest(
    string RefreshToken, 
    string? PushNotificationToken
);
