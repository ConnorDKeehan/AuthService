using AuthService.Interfaces;
using AuthService.Models.Entities;
using AuthService.Models.Requests;
using Google.Apis.Auth;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using AuthService.Models.Responses;
using Azure.Core;
using AuthService.Models.Enums;
using Microsoft.AspNetCore.Http;
using AuthService.Extensions;

namespace AuthService.Services;

public class AuthService : IAuthService
{
    private readonly IConfiguration configuration;
    private readonly ILoginsRepository loginsRepository;
    private readonly IRefreshTokensRepository refreshTokensRepository;
    private readonly ITwoFactorAuthCodesRepository twoFactorAuthCodesRepository;
    private readonly IEmailService emailService;
    private readonly string? GoogleClientId;
    private readonly string? GoogleClientSecret;
    private readonly string? AppleClientId;

    public AuthService(IConfiguration configuration, ILoginsRepository loginsRepository, IRefreshTokensRepository refreshTokensRepository,
        ITwoFactorAuthCodesRepository twoFactorAuthCodesRepository, IEmailService emailService)
    {
        this.configuration = configuration;
        this.loginsRepository = loginsRepository;
        this.refreshTokensRepository = refreshTokensRepository;
        this.twoFactorAuthCodesRepository = twoFactorAuthCodesRepository;
        this.emailService = emailService;
        GoogleClientId = configuration["Auth:GoogleClientId"];
        GoogleClientSecret = configuration["Auth:GoogleClientSecret"];
        AppleClientId = configuration["Auth:AppleClientId"];
    }

    public async Task RegisterAsync(RegisterRequest request)
    {
        var email = string.IsNullOrWhiteSpace(request.Email) ? null : request.Email;

        if (await loginsRepository.DoesThisUserAlreadyExistAsync(request.Username, email))
        {
            throw new ArgumentException("Username already taken");
        }

        var hashedPassword = BCrypt.Net.BCrypt.HashPassword(request.Password);

        var login = new Login
        {
            Username = request.Username,
            Email = email,
            Password = hashedPassword,
            PushNotificationToken = request.PushNotificationToken,
            Deleted = false,
            AccessTokenVersion = 1,
            DateCreatedUtc = DateTime.UtcNow,
        };

        await loginsRepository.AddLoginAsync(login);
    }

    public async Task<TokenResponse> LoginAsync(LoginRequest request)
    {
        var login = await loginsRepository.GetLoginByUsernameAsync(request.Username);

        if (login == null || !BCrypt.Net.BCrypt.Verify(request.Password, login.Password))
        {
            throw new ArgumentException($"Invalid username or password.");
        }

        if (request.PushNotificationToken != null)
        {
            await loginsRepository.UpdatePushNotificationTokenAsync(login.Id, request.PushNotificationToken);
        }

        var deviceId = Guid.NewGuid();
        var result = await GenerateAndSaveTokensAsync(login, deviceId);

        return result;
    }

    public async Task<TokenResponse> RefreshTokensAsync(int loginId, string refreshToken, string? pushNotificationToken, Guid deviceId)
    {
        await EnsureRefreshTokenIsValid(refreshToken, loginId);

        var login = await loginsRepository.GetLoginByIdAsync(loginId);

        if (!string.IsNullOrWhiteSpace(pushNotificationToken))
        {
            await loginsRepository.UpdatePushNotificationTokenAsync(login.Id, pushNotificationToken);
        }

        var result = await GenerateAndSaveTokensAsync(login, deviceId);

        return result;
    }

    public async Task<TokenResponse> LoginWithSocialAsync(LoginWithSocialRequest request)
    {
        string? userEmail;
        string? socialLoginIdentifier = null;
        Login? userLogin = null;

        if(!Enum.TryParse<SocialLoginProvidersEnum>(request.Provider, ignoreCase: true, out var provider))
        {
            throw new ArgumentException($"{request.Provider} is not a valid provider");
        }

        switch (provider)
        {
            case SocialLoginProvidersEnum.Google:

                if(GoogleClientId.IsNullOrEmpty() || GoogleClientSecret.IsNullOrEmpty())
                {
                    throw new ArgumentNullException("Auth:GoogleClientId and Auth:GoogleClientSecret must be in appsettings and not null or empty");
                }

                var googleIdToken = await ExchangeCodeForIdTokenAsync(request.IdToken);

                var googlePayload = await GoogleJsonWebSignature.ValidateAsync(
                    googleIdToken,
                    new GoogleJsonWebSignature.ValidationSettings
                    {
                        Audience = new[] { GoogleClientId },
                    }
                );

                userEmail = googlePayload.Email;
                socialLoginIdentifier = googlePayload.Email;
                userLogin = await loginsRepository.GetLoginByEmailAsync(userEmail);
                break;

            case SocialLoginProvidersEnum.Apple:
                if (AppleClientId.IsNullOrEmpty())
                {
                    throw new ArgumentNullException("Auth:AppleClientId must be in appsettings and not null or empty");
                }

                var appleClaimsPrincipal = await ValidateAppleIdTokenAsync(request.IdToken);

                userEmail = appleClaimsPrincipal.FindFirstValue(ClaimTypes.Email);
                socialLoginIdentifier = appleClaimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);

                userLogin = await loginsRepository.GetLoginBySocialIdentifierAsync(socialLoginIdentifier!);
                break;

            default:
                throw new NotImplementedException("No setup for the provider");
        }

        if (userLogin == null)
        {
            userLogin = new Login
            {
                Username = userEmail ?? Guid.NewGuid().ToString(),
                Email = userEmail,
                Password = "placeholder",
                PushNotificationToken = request.PushNotificationToken,
                SocialLoginIdentifier = socialLoginIdentifier,
                Deleted = false,
                AccessTokenVersion = 1,
                DateCreatedUtc = DateTime.UtcNow,
            };
            await loginsRepository.AddLoginAsync(userLogin);
        }

        var tokenResponse = await GenerateAndSaveTokensAsync(userLogin, Guid.NewGuid());
        return tokenResponse;
    }

    private async Task EnsureRefreshTokenIsValid(string refreshToken, int loginId)
    {
        var hashedToken = HashString(refreshToken);

        var matchedRefreshToken = await refreshTokensRepository.GetRefreshTokenByHashAndLoginIdAsync(hashedToken, loginId);

        if(matchedRefreshToken == null || 
            matchedRefreshToken.DateExpiryUtc < DateTime.UtcNow || 
            matchedRefreshToken.Revoked == true)
        {
            throw new UnauthorizedAccessException("Refresh Token is invalid");
        } 
    }

    private async Task<string> ExchangeCodeForIdTokenAsync(string authCode)
    {
        using var client = new HttpClient();

        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("code", authCode),
            new KeyValuePair<string, string>("client_id", GoogleClientId!),
            new KeyValuePair<string, string>("client_secret", GoogleClientSecret!),
            new KeyValuePair<string, string>("redirect_uri", ""),
            new KeyValuePair<string, string>("grant_type", "authorization_code")
        });

        var response = await client.PostAsync("https://oauth2.googleapis.com/token", content);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty("id_token", out var idTokenElement))
        {
            throw new Exception("id_token not found in Google token exchange response.");
        }
        return idTokenElement.GetString()!;
    }

    public async Task DeleteLoginAsync(int loginId, string password)
    {
        await VerifyLoginPasswordAsync(loginId, password);

        await loginsRepository.DeleteLoginAsync(loginId);
    }

    public async Task<TokenResponse> UpdatePasswordWithPasswordAsync(int loginId, UpdatePasswordWithPasswordRequest updatePasswordRequest, Guid deviceId)
    {
        await VerifyLoginPasswordAsync(loginId, updatePasswordRequest.oldPassword);
        var login = await loginsRepository.GetLoginByIdAsync(loginId);

        if(login.Email != null)
        {
            throw new Exception("Updating password with password is only avaliable for users without emails for 2FA");
        }

        var hashedPassword = BCrypt.Net.BCrypt.HashPassword(updatePasswordRequest.newPassword);

        await UpdatePasswordAsync(loginId, hashedPassword);
        var result = await GenerateAndSaveTokensAsync(login, deviceId);

        return result;
    }

    

    public async Task UpdateMetadataAsync(int loginId, string metadata)
    {
        await loginsRepository.UpdateMetadataAsync(loginId, metadata);
    }

    public async Task<int> SendForgotPasswordCodeAsync(SendForgotPasswordCodeRequest request)
    {
        if (request.username == null && request.email == null)
        {
            throw new ArgumentException("Must provide either email or username");
        }

        var login = request.username != null
            ? await loginsRepository.GetLoginByUsernameAsync(request.username)
            : await loginsRepository.GetLoginByUsernameAsync(request.email!);

        if (login == null)
        {
            throw new ArgumentException("User with that username/email doesn't exist");
        }

        if(login.Email == null)
        {
            throw new Exception("This user is not setup with an email");
        }

        var codeId = await SendTwoFactorAuthCodeAsync(login.Id, login.Email, TwoFactorAuthCodePurposesEnum.ResetPassword);

        return codeId;
    }

    public async Task<int> SendVerifyEmailCodeAsync(int loginId)
    {
        var login = await loginsRepository.GetLoginByIdAsync(loginId);

        if (login.Email == null)
        {
            throw new Exception("This user is not setup with an email");
        }

        var codeId = await SendTwoFactorAuthCodeAsync(login.Id, login.Email, TwoFactorAuthCodePurposesEnum.VerifyEmail);

        return codeId;
    }

    public async Task<TokenResponse> UpdatePasswordWithCodeAsync(UpdatePasswordWithCodeRequest request)
    {
        await ValidateAndRevokeTwoFactorAuthCodeAsync(request.code, request.twoFactorAuthCodeId, TwoFactorAuthCodePurposesEnum.ResetPassword, null);

        var twoFactorAuthCode = await twoFactorAuthCodesRepository.GetTwoFactorAuthCodeByIdAsync(request.twoFactorAuthCodeId);

        await UpdatePasswordAsync(twoFactorAuthCode.LoginId, request.newPassword);
        var login = await loginsRepository.GetLoginByIdAsync(twoFactorAuthCode.LoginId);
        var result = await GenerateAndSaveTokensAsync(login, Guid.NewGuid());

        return result;
    }

    public async Task VerifyEmailAsync(int loginId, string code, int twoFactorAuthCodeId)
    {
        var login = await loginsRepository.GetLoginByIdAsync(loginId);
        await ValidateAndRevokeTwoFactorAuthCodeAsync(code, twoFactorAuthCodeId, TwoFactorAuthCodePurposesEnum.VerifyEmail, login);

        await loginsRepository.MarkEmailAsVerifiedAsync(loginId);
    }

    private async Task ValidateAndRevokeTwoFactorAuthCodeAsync(string code, int twoFactorAuthCodeId, TwoFactorAuthCodePurposesEnum purpose, Login? login)
    {
        var twoFactorAuthCode = await twoFactorAuthCodesRepository.GetTwoFactorAuthCodeByIdAsync(twoFactorAuthCodeId);

        if (twoFactorAuthCode.DateExpiryUtc < DateTime.UtcNow) {
            throw new ArgumentException("Code has expired");
        }

        if (twoFactorAuthCode.Revoked)
        {
            throw new ArgumentException("Code has been already been used or otherwise revoked");
        }

        if (Enum.Parse<TwoFactorAuthCodePurposesEnum>(twoFactorAuthCode.Purpose) != purpose) 
        {
            throw new ArgumentException("Code was not made for the purpose it is being used for");
        }

        if(login != null && twoFactorAuthCode.LoginId != login.Id)
        {
            throw new UnauthorizedAccessException("Code attempting to be used is for a different login");
        }

        var hashedCode = HashString(code);

        if (twoFactorAuthCode.Code != hashedCode) 
        {
            throw new ArgumentException("Entered 2FA code did not match");
        }

        await twoFactorAuthCodesRepository.MarkTwoFactorAuthCodeAsUsedAsync(twoFactorAuthCodeId);
    }

    private async Task UpdatePasswordAsync(int loginId, string password)
    {
        var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

        await loginsRepository.UpdatePasswordAsync(loginId, hashedPassword);
    }

    private async Task<int> SendTwoFactorAuthCodeAsync(int loginId, string email, TwoFactorAuthCodePurposesEnum purpose)
    {
        var number = RandomNumberGenerator.GetInt32(0, 1_000_000); // 0 to 999999
        var code = number.ToString("D6");
        var hashedCode = HashString(code);

        var codeId = await twoFactorAuthCodesRepository.AddTwoFactorAuthCodeAsync(loginId, hashedCode, purpose);

        var emailBody = $"Your one time code is: {code}";
        await emailService.SendAsync(email, purpose.GetDescription(), emailBody);

        return codeId;
    }

    private async Task VerifyLoginPasswordAsync(int loginId, string password)
    {
        var login = await loginsRepository.GetLoginByIdAsync(loginId);

        if (login == null)
        {
            throw new ArgumentException($"Login {loginId} does not exist");
        }

        if (!BCrypt.Net.BCrypt.Verify(password, login.Password))
        {
            throw new ArgumentException("Incorrect password");
        }
    }

    private async Task<ClaimsPrincipal> ValidateAppleIdTokenAsync(string appleIdToken)
    {
        var handler = new JwtSecurityTokenHandler();

        var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "https://appleid.apple.com/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever()
        );
        var appleOpenIdConfig = await configManager.GetConfigurationAsync();

        var validationParameters = new TokenValidationParameters
        {
            ValidIssuer = "https://appleid.apple.com",
            IssuerSigningKeys = appleOpenIdConfig.SigningKeys,
            ValidAudience = AppleClientId!,
            ValidateAudience = true,
        };

        var claimsPrincipal = handler.ValidateToken(appleIdToken, validationParameters, out _);
        return claimsPrincipal;
    }

    private async Task<TokenResponse> GenerateAndSaveTokensAsync(Login login, Guid deviceId)
    {
        var accessToken = GenerateJwtToken(login, deviceId);
        var refreshToken = GenerateRefreshToken();
        var hashedRefreshToken = HashString(refreshToken);

        var expiryTimeDays = configuration.GetValue<int>("Auth:RefreshTokenExpiryTimeDays");
        await refreshTokensRepository.UpdateRefreshTokenByLoginAndDeviceAsync(hashedRefreshToken, deviceId, login.Id, expiryTimeDays);
        return new TokenResponse(accessToken, refreshToken);
    }

    private string GenerateJwtToken(Login user, Guid deviceId)
    {
        //These are all validated in DI to not be null.
        string jwtIssuer = configuration["Auth:Jwt:Issuer"]!;
        string jwtKey = configuration["Auth:Jwt:Key"]!;
        string jwtAudience = configuration["Auth:Jwt:Audience"]!;
        int expiryTimeMinutes = configuration.GetValue<int>("Auth:Jwt:ExpiryTimeMinutes");

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Username),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("LoginId", user.Id.ToString()),
            new Claim("TokenVersion", user.AccessTokenVersion.ToString()),
            new Claim("DeviceId", deviceId.ToString())
        };

        var token = new JwtSecurityToken(
            jwtIssuer,
            jwtAudience,
            claims,
            expires: DateTime.UtcNow.AddMinutes(expiryTimeMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    private string HashString(string value)
    {
        var refreshTokenHmacKey = configuration["Auth:RefreshTokenHmacKey"]!;
        var keyBytes = Encoding.UTF8.GetBytes(refreshTokenHmacKey);
        var tokenBytes = Encoding.UTF8.GetBytes(value);

        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(tokenBytes);
        return Convert.ToBase64String(hash);
    }
}
