using System.ComponentModel.DataAnnotations;

namespace Jwt_Auth.Model
{
    public class User
    {
        [Key]
        public int userid { get; set; }

        public string username { get; set; }

        public string password { get; set; }
     
        public string email { get; set; }
        public string Role { get; set; }
        public string Token { get; set; }
    }
}
