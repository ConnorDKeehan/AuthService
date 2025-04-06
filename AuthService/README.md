Currently this package requires a few things: A Logins table and RefreshTokens table created in your database.
This script is in the SqlScripts folder of the Nuget package and also below:

``` sql
CREATE TABLE Logins (
    Id INT PRIMARY KEY IDENTITY(1,1) NOT NULL,
    Username NVARCHAR(100) NOT NULL,
    Email NVARCHAR(100) NULL,
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