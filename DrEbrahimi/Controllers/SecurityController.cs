using DrEbrahimi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DrEbrahimi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecurityController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _manager;
        private readonly IConfiguration _config;

        public SecurityController(UserManager<ApplicationUser> manager, IConfiguration config)
        {
            _manager = manager;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Register model)
        {
            try
            {
                if (model.Password != model.ConfirmPassword)
                {
                    return BadRequest("Password and Confirm Password do not match.");
                }

                var user = new ApplicationUser
                {
                    UserName = model.UserName,
                    Email = model.Email,
                    SecurityQuestion = model.SecurityQuestion,
                    SecurityAnswer = model.SecurityAnswer
                };

                var result = await _manager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    var token = await _manager.GenerateEmailConfirmationTokenAsync(user);
                    var confirmationLink = Url.Action(nameof(ConfirmEmail), "Security", new { userName = user.UserName, token }, Request.Scheme);

                    // Send confirmation email here
                    return Ok(new { Message = "User registered successfully. Please check your email to confirm your account." });
                }

                return BadRequest(result.Errors);
            }
            catch (Exception ex)
            {
                throw new Exception("Message", ex);
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            try
            {
                var user = await _manager.FindByNameAsync(model.UserName);
                if (user == null || !await _manager.CheckPasswordAsync(user, model.Password))
                {
                    return Unauthorized("Invalid username or password.");
                }

                var token = GenerateJwtToken(user);
                return Ok(new { Token = token });
            }
            catch (Exception ex)
            {
                throw new Exception("Message", ex);
            }
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config["Jwt:Key"]);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name, user.UserName)
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userName, string token)
        {
            try
            {
                var user = await _manager.FindByIdAsync(userName);

                if (user == null)
                    return BadRequest("Invalid user name");

                var result = await _manager.ConfirmEmailAsync(user, token);

                if (result.Succeeded)
                    return Ok("Email confirmed successfully!");

                return BadRequest("Email confirmation failed.");
            }
            catch (Exception ex)
            {
                throw new Exception("Message", ex);
            }
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] string email)
        {
            try
            {
                var user = await _manager.FindByEmailAsync(email);

                if (user == null)
                {
                    return BadRequest("User with this email does not exist.");
                }

                var token = await _manager.GeneratePasswordResetTokenAsync(user);
                var resetLink = Url.Action(nameof(ResetPassword), "Security", new { token, email = user.Email }, Request.Scheme);

                // Send reset email here
                return Ok("Password reset link has been sent to your email.");
            }
            catch (Exception ex)
            {
                throw new Exception("Message", ex);
            }
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
        {
            try
            {
                var user = await _manager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    return BadRequest("User with this email does not exist.");
                }

                var result = await _manager.ResetPasswordAsync(user, model.Token, model.NewPassword);

                if (result.Succeeded)
                {
                    return Ok("Password has been reset successfully!");
                }

                return BadRequest(result.Errors);
            }
            catch (Exception ex)
            {
                throw new Exception("Messsage", ex);
            }
        }
    }
}
