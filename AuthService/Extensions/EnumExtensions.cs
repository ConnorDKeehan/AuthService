﻿using System.ComponentModel;
using System.Reflection;

namespace AuthService.Extensions;

internal static class EnumExtensions
{
    public static string GetDescription(this Enum value)
    {
        var field = value.GetType().GetField(value.ToString());

        if (field?.GetCustomAttribute<DescriptionAttribute>() is DescriptionAttribute attr)
        {
            return attr.Description;
        }

        return value.ToString();
    }
}