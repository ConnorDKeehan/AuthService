namespace AuthService.Models;

public record SmtpSettings(string Host, int Port, string Username, string Password, string From, bool EnableSsl);