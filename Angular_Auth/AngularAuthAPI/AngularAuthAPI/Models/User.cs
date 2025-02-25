using System.ComponentModel.DataAnnotations;

namespace AngularAuthAPI.Models
{
    public class User
    {
        [Key]
        public int UserId { get; set; }
        public string Username { get; set; }
        public string Firstname { get; set; }
        public string Lastname { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Token {  get; set; }
        public string Role { get; set; }
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpireTime { get; set; }
    }
}
