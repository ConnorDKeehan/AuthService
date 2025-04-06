This is the host repo for the Nuget package: ConnorDKeehan.AuthService.

You can add the nuget package to your own repo or you can use this project to host the standalone auth api.

Currently this package requires a few things:

Create the necessary tables in the database you plan to use.
This script is in the SqlScripts folder of the Nuget package and also below:

``` sql
CREATE TABLE Logins (
    Id INT PRIMARY KEY IDENTITY(1,1) NOT NULL,
    Username NVARCHAR(100) NOT NULL,
    Email NVARCHAR(100) NULL,
    EmailVerified BIT NOT NULL,
    Password NVARCHAR(200) NOT NULL,
    AccessTokenVersion INT NOT NULL,
    Deleted BIT NOT NULL,
    PushNotificationToken NVARCHAR(200) NULL,
    SocialLoginIdentifier NVARCHAR(100) NULL,
    DateCreatedUtc DATETIME2,
    Metadata NVARCHAR(MAX) NULL
)

CREATE TABLE RefreshTokens (
    Id INT PRIMARY KEY IDENTITY(1,1) NOT NULL,
    LoginId INT NOT NULL REFERENCES Logins(Id),
    Token NVARCHAR(200) NOT NULL UNIQUE,
    DeviceId UNIQUEIDENTIFIER NOT NULL,
    DateCreatedUtc DATETIME2 NOT NULL,
    DateExpiryUtc DATETIME2 NOT NULL,
    Revoked BIT NOT NULL
)

CREATE TABLE TwoFactorAuthCodes (
    Id INT PRIMARY KEY IDENTITY(1,1) NOT NULL,
    LoginId INT NOT NULL REFERENCES Logins(Id),
    Code NVARCHAR(50) NOT NULL,
    Purpose NVARCHAR(50) NOT NULL,
    DateCreatedUtc DATETIME2 NOT NULL,
    DateExpiryUtc DATETIME2 NOT NULL,
    DateUsedUtc DATETIME2 NULL,
    Revoked BIT NOT NULL
)
```

You will also need to add the DI to your startup:
```cs
builder.Services.AddAuthService(builder.Configuration);
```


Some appsettings to be set, particularly:
1. "Auth:Jwt:Issuer"
2. "Auth:Jwt:Key"
3. "Auth:Jwt:Audience"
4. "Auth:ExpiryTimeMinutes"
5. "Auth:ConnectionString" //For most people this will be the same as their default connection string, just duplicate it to there in that case.
6. "Auth:RefreshTokenHmacKey"
7. "Auth:RefreshTokenExpiryTimeDays"

And if you'd like to allow login with google account:
1. "Auth:GoogleClientId"
2. "Auth:GoogleClientSecret"

Similarly for Apple login you will need:
1. "Auth:AppleClientId"

If you wish to use the default EmailService in the package you will need to include the below:
1. "Auth:EnableDefaultEmailService": true
2. "Auth:Smtp:Host"
3. "Auth:Smtp:Port"
4. "Auth:Smtp:Username"
5. "Auth:Smtp:Password"
6. "Auth:Smtp:From"
7. "Auth:Smtp:EnableSsl"

If you don't choose to use the default email service you will need to register your own if you want to use the 2FA features:
```cs
builder.Services.AddScoped<IEmailService,MyCustomEmailService>();
```

And it must implement:
```cs
Task SendAsync(string to, string subject, string body);
```
