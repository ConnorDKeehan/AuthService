using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Extensions;

internal static class GuidExtensions
{
    internal static Guid? TryParseGuid(this string value)
    {
        return Guid.TryParse(value, out var guid) && guid != Guid.Empty
            ? guid
            : null;
    }
}
