using AuthService.Models.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Contexts;

public class AuthContext : DbContext
{
    public AuthContext(DbContextOptions<AuthContext> options) : base(options)
    {
    }

    public DbSet<Login> Logins { get; set; }
}
