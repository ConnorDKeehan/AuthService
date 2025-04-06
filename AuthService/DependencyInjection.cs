using AuthService.Contexts;
using AuthService.Controllers;
using AuthService.Interfaces;
using AuthService.Models;
using AuthService.Repositories;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel;
using System.Text;

namespace AuthService;

public static class DependencyInjection
{
    public static IServiceCollection AddAuthService(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        string jwtKey = GetAndValidateConfigValue<string>("Auth:Jwt:Key", configuration);
        string jwtAudience = GetAndValidateConfigValue<string>("Auth:Jwt:Audience", configuration);
        string jwtIssuer = GetAndValidateConfigValue<string>("Auth:Jwt:Issuer", configuration);
        string expiryTimeMinutes = GetAndValidateConfigValue<string>("Auth:Jwt:ExpiryTimeMinutes", configuration);
        string connectionString = GetAndValidateConfigValue<string>("Auth:ConnectionString", configuration);
        string refreshToken = GetAndValidateConfigValue<string>("Auth:RefreshTokenHmacKey", configuration); 
        int refreshTokenExpiryTime = GetAndValidateConfigValue<int>("Auth:RefreshTokenExpiryTimeDays", configuration);

        services.AddControllers()
            .AddApplicationPart(typeof(AuthController).Assembly)
            .AddControllersAsServices();

        services.AddDbContext<AuthContext>(options =>
            options.UseSqlServer(connectionString));

        services.AddScoped<IAuthService, Services.AuthService>();
        services.AddScoped<ILoginsRepository, LoginsRepository>();
        services.AddScoped<IRefreshTokensRepository, RefreshTokensRepository>();
        services.AddScoped<ITwoFactorAuthCodesRepository, TwoFactorAuthCodesRepository>();
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

        bool.TryParse(configuration["EnableDefaultEmailService"], out bool enableDefaultEmailService);


        services.AddEmailService(configuration);

        return services;
    }

    private static IServiceCollection AddEmailService(this IServiceCollection services, IConfiguration configuration)
    {
        // Don't override hosts implementation if there is one.
        if (services.Any(sd => sd.ServiceType == typeof(IEmailService)))
        {
            return services;
        }

        bool.TryParse(configuration["Auth:EnableDefaultEmailService"], out bool enableDefaultEmailService);

        if (enableDefaultEmailService)
        {
            //If default email service is enabled all the below must be present in appsettings.json
            var host = GetAndValidateConfigValue<string>("Auth:Smtp:Host", configuration);
            var port = GetAndValidateConfigValue<int>("Auth:Smtp:Port", configuration);
            var username = GetAndValidateConfigValue<string>("Auth:Smtp:Username", configuration);
            var password = GetAndValidateConfigValue<string>("Auth:Smtp:Password", configuration);
            var from = GetAndValidateConfigValue<string>("Auth:Smtp:From", configuration);
            var enableSSl = GetAndValidateConfigValue<bool>("Auth:Smtp:EnableSsl", configuration);

            services.AddScoped<IEmailService>(sp =>
            {
                var settings = new SmtpSettings(host, port, username, password, from, enableSSl);
                return new EmailService(settings);
            });

            return services;
        }

        services.AddScoped<IEmailService, FallbackEmailService>();

        return services;
    }

    private static T GetAndValidateConfigValue<T>(string configKey, IConfiguration configuration)
    {
        string? configValue = configuration[configKey];

        if (string.IsNullOrWhiteSpace(configValue))
        {
            throw new ArgumentNullException(configKey, $"{configKey} is required in appsettings");
        }

        var converter = TypeDescriptor.GetConverter(typeof(T));

        if (!converter.CanConvertFrom(typeof(string)))
        {
            throw new InvalidOperationException($"Cannot convert {configValue} to {typeof(T).Name}");
        }

        try
        {
            return (T)converter.ConvertFromInvariantString(configValue)!;
        }
        catch
        {
            throw new FormatException($"{configKey} must be a valid {typeof(T).Name}");
        }
    }
}
