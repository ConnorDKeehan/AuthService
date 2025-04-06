using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Models.Requests;

public record SendForgotPasswordCodeRequest(string? username, string? email);