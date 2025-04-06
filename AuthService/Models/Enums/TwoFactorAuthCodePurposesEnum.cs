using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Models.Enums;

public enum TwoFactorAuthCodePurposesEnum
{
    [Description("Reset Password")]
    ResetPassword,

    [Description("Verify Email")]
    VerifyEmail,

    [Description("Update Email")]
    ChangeEmail,

    [Description("Delete Account")]
    DeleteAccount
}
