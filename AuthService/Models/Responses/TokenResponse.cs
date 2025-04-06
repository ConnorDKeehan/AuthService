using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Models.Responses;

public record TokenResponse(
    string JwtToken, 
    string RefreshToken
);
