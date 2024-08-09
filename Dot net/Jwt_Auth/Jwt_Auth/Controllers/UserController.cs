using Jwt_Auth.Helpers;
using Jwt_Auth.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Xml.Linq;

namespace Jwt_Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext appDbContext;

        public UserController(AppDbContext appDbContext)
        {
            this.appDbContext = appDbContext;
        }
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authentication(User user)
        {
            if (user == null)
            {
                return BadRequest();
            }
            var userlist = await appDbContext.Users.FirstOrDefaultAsync(x => x.email == user.email );

            if (userlist == null)
            {
                return NotFound(new { Message = "User Can't Found" });
            }

            //if (!PasswordHash.VerifyPassword(user.password, userlist.password))
            //{
            //    return BadRequest(new
            //    {
            //        Message = "Password is Incorrect"
            //    });
            //}

            //userlist.Token= CreateJwtToke(userlist);

            return Ok(new {

                Message = "Login SuccesFully",
                Token = CreateJwtToke(userlist),
            }); 
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User user)
        {
            if (user == null)
            {
                return BadRequest();
            }

            //user.password = PasswordHash.HashPassword(user.password);
            user.Role = "User";
            user.Token = "";
            await appDbContext.Users.AddAsync(user);

            await appDbContext.SaveChangesAsync();

            return Ok(new
            {
                Message = "Data Added"
            });
        }

        private string CreateJwtToke(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("your_new_very_long_secret_key_here");
            var identity = new ClaimsIdentity(new Claim[]
            {
                       new Claim(ClaimTypes.Role,user.Role),
                       new Claim(ClaimTypes.Name,user.username),
              });
            var crediantial = new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256);
            var TokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddMinutes(15),
                SigningCredentials = crediantial,
            };
            var token = jwtTokenHandler.CreateToken(TokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        [HttpGet]
        [Authorize]
        public async Task<ActionResult<User>> GetAllUser()
        {
            return Ok(await appDbContext.Users.ToListAsync());
        }

        [HttpDelete("{id}")]
        [Authorize]
        public async Task<ActionResult> deleteUser(int id)
        {     
            var userlist = appDbContext.Users.Find(id);
            appDbContext.Remove(userlist);
            appDbContext.SaveChanges();
            return Ok(new
            {
                Message="Data Successfully Deleted"
            });
        }        
     
    }
}
