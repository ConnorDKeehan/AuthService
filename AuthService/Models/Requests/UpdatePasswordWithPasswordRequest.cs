namespace AuthService.Models.Requests;

public record UpdatePasswordWithPasswordRequest(string oldPassword, string newPassword);
