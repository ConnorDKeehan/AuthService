namespace AuthService.Models.Responses;

public record TokenResponse(
    string JwtToken, 
    string RefreshToken
);
