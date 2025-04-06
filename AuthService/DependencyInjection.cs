using AuthService.Contexts;
using AuthService.Controllers;
using AuthService.Interfaces;
using AuthService.Repositories;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace AuthService;

public static class DependencyInjection
{
    public static IServiceCollection AddAuthService(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        string jwtKey = GetAndValidateConfigValue("Auth:Jwt:Key", configuration);
        string jwtAudience = GetAndValidateConfigValue("Auth:Jwt:Audience", configuration);
        string jwtIssuer = GetAndValidateConfigValue("Auth:Jwt:Issuer", configuration);
        string expiryTimeMinutes = GetAndValidateConfigValue("Auth:Jwt:ExpiryTimeMinutes", configuration);
        string connectionString = GetAndValidateConfigValue("Auth:ConnectionString", configuration);
        string refreshToken = GetAndValidateConfigValue("Auth:RefreshTokenHmacKey", configuration); 
        string refreshTokenExpiryTime = GetAndValidateConfigValue("Auth:RefreshTokenExpiryTimeDays", configuration);

        services.AddControllers()
            .AddApplicationPart(typeof(AuthController).Assembly)
            .AddControllersAsServices();

        services.AddDbContext<AuthContext>(options =>
            options.UseSqlServer(connectionString));

        services.AddScoped<IAuthService, Services.AuthService>();
        services.AddScoped<ILoginsRepository, LoginsRepository>();
        services.AddScoped<IRefreshTokensRepository, RefreshTokensRepository>();
        services.AddScoped<ITokenValidationService, TokenValidationService>();

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtIssuer,
                ValidAudience = jwtAudience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!))
            };

            options.Events = new JwtBearerEvents
            {
                OnTokenValidated = async context =>
                {
                    var tokenValidationService = context.HttpContext.RequestServices.GetRequiredService<ITokenValidationService>();
                    var valid = await tokenValidationService.ValidateAsync(context.Principal);

                    if (!valid)
                    {
                        context.Fail("Token is no longer valid.");
                        return;
                    }
                }
            };
        });

        services.AddAuthorization(options =>
        {
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();
        });

        return services;
    }

    private static string GetAndValidateConfigValue(string configKey, IConfiguration configuration)
    {
        string? configValue = configuration[configKey];

        if (string.IsNullOrWhiteSpace(configValue))
        {
            throw new ArgumentNullException(configKey, $"{configKey} is required in appsettings");
        }

        return configValue;
    }
}
