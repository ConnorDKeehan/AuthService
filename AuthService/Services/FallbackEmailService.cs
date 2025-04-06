using AuthService.Interfaces;

namespace AuthService.Services;

public class FallbackEmailService : IEmailService
{
    public Task SendAsync(string to, string subject, string body)
    {
        throw new NotImplementedException("No implementation of EmailService has been registered");
    }
}
