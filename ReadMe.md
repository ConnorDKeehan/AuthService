Currently this package requires a few things:
A Logins table with the required columns created in your database.


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

"Auth:AppleClientId"
