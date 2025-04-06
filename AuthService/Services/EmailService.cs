using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using AuthService.Interfaces;
using AuthService.Models;
using Microsoft.Extensions.Options;

public class EmailService(SmtpSettings settings) : IEmailService
{
    public async Task SendAsync(string to, string subject, string body)
    {
        using var message = new MailMessage
        {
            From = new MailAddress(settings.From),
            Subject = subject,
            Body = body,
            IsBodyHtml = false,
        };

        message.To.Add(to);

        using var client = new SmtpClient(settings.Host, settings.Port)
        {
            EnableSsl = settings.EnableSsl,
            Credentials = new NetworkCredential(settings.Username, settings.Password),
        };

        await client.SendMailAsync(message);
    }
}