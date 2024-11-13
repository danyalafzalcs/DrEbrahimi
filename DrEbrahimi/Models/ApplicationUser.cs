using Microsoft.AspNetCore.Identity;

namespace DrEbrahimi.Models
{
    public class ApplicationUser : IdentityUser

    {

        public string SecurityQuestion { get; set; }
        public string SecurityAnswer { get; set; }
        public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
        

    }
}
