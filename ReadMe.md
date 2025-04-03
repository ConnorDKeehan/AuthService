#Read me

Currently ths package requires a few things:
A Logins table with the required columns created in your database.

Some appsettings to be set, particularly:
"Auth:Jwt:Issuer"
"Auth:Jwt:Key"
"Auth:Jwt:Audience"
"Auth:ExpiryTimeMinutes"
"Auth:ConnectionString" //For most people this will be the same as their default connection string, just duplicate it to there in that case.

And if you'd like to allow login with google account:
"Auth:GoogleClientId"
"Auth:GoogleClientSecret"

Similarly for Apple login you will need:
"Auth:AppleClientId"