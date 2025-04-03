Currently this package requires a few things:
A Logins table with the required columns created in your database.
``` sql
CREATE TABLE Logins (
    Id INT PRIMARY KEY IDENTITY(1,1) NOT NULL,
    Username NVARCHAR(100) NOT NULL,
    Email NVARCHAR(100) NULL,
    Password NVARCHAR(200) NOT NULL,
    TokenVersion INT NOT NULL,
    Deleted BIT NOT NULL,
    PushNotificationToken NVARCHAR(200) NULL,
    SocialLoginIdentifier NVARCHAR(100) NULL,
    DateCreated DATETIMEOFFSET,
    Metadata NVARCHAR(MAX) NULL
)
```

Some appsettings to be set, particularly:
1. "Auth:Jwt:Issuer"
2. "Auth:Jwt:Key"
3. "Auth:Jwt:Audience"
4. "Auth:ExpiryTimeMinutes"
5. "Auth:ConnectionString" //For most people this will be the same as their default connection string, just duplicate it to there in that case.


And if you'd like to allow login with google account:
1. "Auth:GoogleClientId"
2. "Auth:GoogleClientSecret"


Similarly for Apple login you will need:
1. "Auth:AppleClientId"
