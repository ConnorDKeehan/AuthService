﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Models.Entities;
public class TwoFactorAuthCode
{
    public int Id { get; set; }
    public int LoginId { get; set; }
    public required string Code { get; set; }
    public required string Purpose {  get; set; }
    public DateTime DateCreatedUtc { get; set; }
    public DateTime DateExpiryUtc { get; set; }
    public DateTime? DateUsedUtc { get; set; }
    public bool Revoked { get; set; }
}
