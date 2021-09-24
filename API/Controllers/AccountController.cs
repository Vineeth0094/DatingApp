using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Interfaces;
using API.Properties.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace API.Controllers
{
    public class AccountController:BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService  tokenService){
            
            _context=context;
            _tokenService = tokenService;
        }
        [HttpPost("register")]
        public async Task<ActionResult<UserDTo>> Register(RegisterDTo registerDTO){
            if(await UserExists(registerDTO.Username)) return BadRequest("usernmae is taken");
            using var hmac= new HMACSHA512();

            var user = new AppUser
            {
                UserName=registerDTO.Username.ToLower(),
                PasswordHash= hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
                PasswordSalt= hmac.Key
            };
            _context.Users.Add(user);

            await _context.SaveChangesAsync();
            return new UserDTo
            {
                Username=user.UserName,
                token= _tokenService.CreateToken(user)
            };
            
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDTo>> login(LoginDTo loginDTo){
            var user =await _context.Users.SingleOrDefaultAsync(x =>x.UserName==loginDTo.Username);

            if(user==null) return Unauthorized("invalid user name");

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDTo.Password));

            for(int i=0; i<computedHash.Length;i++){
                if(computedHash[i]!= user.PasswordHash[i]) return Unauthorized("wrong password");
            }

            return new UserDTo
            {
                Username=user.UserName,
                token= _tokenService.CreateToken(user)
            };
        }

        private async Task<bool> UserExists(string username){
            return await _context.Users.AnyAsync(x=>x.UserName==username.ToLower());
        }
        
    }
}