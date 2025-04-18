﻿namespace AuthService.Models.Requests;

public record LoginRequest(
    string Username, 
    string Password, 
    string? PushNotificationToken
);
