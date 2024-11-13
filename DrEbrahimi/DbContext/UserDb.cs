using DrEbrahimi.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace DrEbrahimi.DbContext
{
    public class UserDb : IdentityDbContext<ApplicationUser>
    {
        public UserDb(DbContextOptions options) : base(options)
        {

        }

      public  DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}

