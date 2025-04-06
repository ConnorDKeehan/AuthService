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

namespace AuthService.Services;

public class AuthService : IAuthService
{
    private readonly IConfiguration configuration;
    private readonly ILoginsRepository loginsRepository;
    private readonly IRefreshTokensRepository refreshTokensRepository;
    private readonly string? GoogleClientId;
    private readonly string? GoogleClientSecret;
    private readonly string? AppleClientId;

    public AuthService(IConfiguration configuration, ILoginsRepository loginsRepository, IRefreshTokensRepository refreshTokensRepository)
    {
        this.configuration = configuration;
        this.loginsRepository = loginsRepository;
        this.refreshTokensRepository = refreshTokensRepository;
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

        switch (request.Provider?.ToLower())
        {
            case "google":

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

            case "apple":
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
                throw new Exception("Unsupported social provider");
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
        var hashedToken = HashToken(refreshToken);

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

    public async Task DeleteLoginAsync(int id)
    {
        await loginsRepository.DeleteLoginAsync(id);
    }

    public async Task UpdateMetadataAsync(int loginId, string metadata)
    {
        await loginsRepository.UpdateMetadataAsync(loginId, metadata);
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
        var hashedRefreshToken = HashToken(refreshToken);

        var expiryTimeDays = configuration.GetValue<int>("Auth:RefreshTokenExpiryTimeDays");
        await refreshTokensRepository.UpdateRefreshTokenByLoginAndDevice(hashedRefreshToken, deviceId, login.Id, expiryTimeDays);
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

    private string HashToken(string token)
    {
        var refreshTokenHmacKey = configuration["Auth:RefreshTokenHmacKey"]!;
        var keyBytes = Encoding.UTF8.GetBytes(refreshTokenHmacKey);
        var tokenBytes = Encoding.UTF8.GetBytes(token);

        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(tokenBytes);
        return Convert.ToBase64String(hash);
    }
}
