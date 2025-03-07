using AngularAuthAPI.Database;
using AngularAuthAPI.DTO;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        public UserController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [HttpPost("authenticateuser")]
        public async Task<IActionResult> AuthenticateUser([FromBody] User userObj)
        {
            if (userObj == null) return BadRequest();
            var userExists = AuthDb.Users.FirstOrDefault(x => x.Username == userObj.Username);
            if (userExists == null) return NotFound(new { Messsage = "User not found!" });
            if (!PasswordHasher.VerifyPassword(userObj.Password, userExists.Password))
            {
                return Unauthorized(new { Message = "Username/ password are incorrect!" });
            }
            userExists.Token = CreateUserToken(userExists);
            var newAccessToken = userExists.Token;
            var newRefreshToken = CreateRefreshToken();
            userExists.RefreshToken = newRefreshToken;
            userExists.RefreshTokenExpireTime = DateTime.Now.AddDays(1);

            return Ok(new TokenApiDto
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }
        [HttpPost("registeruser")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null) return BadRequest();

            if (UserNameExists(userObj.Username))
                return BadRequest(new { Message = "username already exists!" });

            if (UserEmailExists(userObj.Email))
                return BadRequest(new { Message = "user email already exists!" });

            var pass = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass });
            var userIndex = AuthDb.Users.OrderBy(u => u.UserId).FirstOrDefault();
            if (userIndex == null) userObj.UserId = 1;
            else userObj.UserId = (userIndex.UserId) + 1;
            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            AuthDb.Users.Add(userObj);
            return Ok(new { Message = "Register success!" });
        }
        private static bool UserNameExists(string username) => AuthDb.Users.Exists(x => x.Username == username);

        private static bool UserEmailExists(string email) => AuthDb.Users.Exists(x => x.Username == email);
        private static string CheckPasswordStrength(string password)
        {
            var errorMessage = new StringBuilder();
            if (password.Length < 8) errorMessage.Append("Minimum password length should be 8" + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[0-9]")))
                errorMessage.Append("Password should be alphanumeric" + Environment.NewLine);
            if (!Regex.IsMatch(password, "[A-Z]"))
                errorMessage.Append("Password should contain caps" + Environment.NewLine);
            if (!Regex.IsMatch(password, @"[!@#$%^&*(),.?""{}|<>]"))
                errorMessage.Append("Password should contain special characters" + Environment.NewLine);
            return errorMessage.ToString();
        }
        private string CreateUserToken(User user)
        {
            var jwtTokenhandler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = null;
            try
            {
                var claimsIdentity = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier,user.UserId.ToString()),
                    new Claim(ClaimTypes.Name, $"{user.Username}"),
                    new Claim(ClaimTypes.Role, user.Role)
                });
                var key = _configuration.GetSection("SecretKey").Value.ToString();
                var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = claimsIdentity,
                    Expires = DateTime.Now.AddMinutes(30),
                    SigningCredentials = credentials
                };
                token = jwtTokenhandler.CreateJwtSecurityToken(tokenDescriptor);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            return jwtTokenhandler.WriteToken(token);
        }
        private string CreateRefreshToken()
        {
            var token = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(token);
            var tokenInUse = AuthDb.Users.Any(x => x.RefreshToken == refreshToken);
            if (tokenInUse) { return CreateRefreshToken(); }
            return refreshToken;
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var key = _configuration.GetSection("SecretKey").Value.ToString();
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key))
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if(jwtSecurityToken != null && !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
            { throw new SecurityTokenException("This token is expired!"); }
            return principal;
        }
        [HttpPost("refreshtoken")]
        public async Task<IActionResult> RefreshToken([FromBody]TokenApiDto tokenDto)
        {
            if (tokenDto is null) return BadRequest("Invalid client request");
            var principal = GetPrincipalFromExpiredToken(tokenDto.AccessToken);
            var username = principal.Identity.Name;
            var userDetails = AuthDb.Users.FirstOrDefault(x=>x.Username == username);
            if(userDetails is null || userDetails.RefreshToken != tokenDto.RefreshToken 
                || userDetails.RefreshTokenExpireTime <= DateTime.Now)
                return BadRequest("Invalid request!");
            var newAccessToken = CreateUserToken(userDetails);
            var newRefreshToken = CreateRefreshToken();
            userDetails.RefreshToken = newRefreshToken;
            return Ok(new TokenApiDto
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });

        }
        [Authorize]
        [HttpGet("getallusers")]
        public ActionResult<User> GetAllUsers()
        {
            return Ok(AuthDb.Users.ToList());
        }
    }
}
