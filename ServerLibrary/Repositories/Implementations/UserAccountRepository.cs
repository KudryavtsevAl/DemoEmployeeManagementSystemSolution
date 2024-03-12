using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Constants = ServerLibrary.Helpers.Constants;

namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository(IOptions<JWTSection> config, AppDbContext appDbContext) : IUserAccount
    {
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            if (user == null) return new GeneralResponse(false, "Model is empty");
            var checkUser = await FindUserByEmail(user.Email!);
            if (checkUser != null) return new GeneralResponse(false, "User already registered");

            var applicationUser = await AddToDb(new ApplicationUser()
            {
                Email = user.Email,
                Name = user.FullName,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });

            // check, create, and assign role
            var checkAdminRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(ar => ar.Name!.Equals(Constants.Admin));
            if (checkAdminRole is null)
            {
                var createAdminRole = await AddToDb(new SystemRole() { Name = Constants.Admin });
                await AddToDb(new UserRole() { RoleId =  createAdminRole.Id , UserId = applicationUser.Id});
                return new GeneralResponse(true, "Acccount created"); 
            }

            var checkUserRole = await appDbContext.SystemRoles.FirstOrDefaultAsync(ur => ur.Name!.Equals(Constants.User));
            var response = new SystemRole(); 
            if (checkUserRole is null) 
            {
                response = await AddToDb(new SystemRole() { Name = Constants.User });
                await AddToDb(new UserRole() { RoleId = response.Id , UserId = applicationUser.Id});
            }
            else 
            {
                await AddToDb(new UserRole() { RoleId = checkUserRole.Id, UserId = applicationUser.Id }); 
            }
            return new GeneralResponse(true, "Account Created"); 
        }

        public async Task<LoginResponse> SignInAsync(Login user)
        {
            if (user is null) return new LoginResponse(false, "Model is empty");

            var applicationUser = await FindUserByEmail(user.Email!);
            if (applicationUser is null) return new LoginResponse(false, "User not found");
            if (!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password)) return new LoginResponse(false, "Invalid credentials");

            var getUserRole = await FindUserRole(applicationUser.Id);
            if (getUserRole is null) return new LoginResponse(false, "User has no role");

            var getRoleName = await FindRoleName(getUserRole.RoleId);
            if (getRoleName is null) return new LoginResponse(false, "User has no role");

            var jwtToken = GenerateToken(applicationUser, getRoleName!.Name!);
            var refreshToken = GenerateRefreshToken();

            var findUser = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(rt => rt.UserId == applicationUser.Id);
            if (findUser is null)
            {
                await AddToDb(new RefreshTokenInfo() { Token = refreshToken, UserId = applicationUser.Id });
            }
            else
            {
                findUser.Token = refreshToken;
                await appDbContext.SaveChangesAsync();
            }
            return new LoginResponse(true, "Login successful", jwtToken, refreshToken);
        }

        private static string GenerateRefreshToken() => BCrypt.Net.BCrypt.HashPassword(BCrypt.Net.BCrypt.GenerateSalt(12));


        private string GenerateToken(ApplicationUser user, string role)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
            var credetnials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userClaims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new(ClaimTypes.Name, user.Name!),
                new(ClaimTypes.Email, user.Email!),
                new(ClaimTypes.Role, role)
            };
            var token = new JwtSecurityToken(
                               issuer: config.Value.Issuer,
                                              audience: config.Value.Audience,
                                                             claims: userClaims,
                                                                            expires: DateTime.Now.AddDays(1),
                                                                                           signingCredentials: credetnials
                                                                                                      );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<UserRole> FindUserRole(int userId) => 
            await appDbContext.UserRoles.FirstOrDefaultAsync(ur => ur.UserId == userId);

        private async Task<SystemRole> FindRoleName (int roleId) => 
            await appDbContext.SystemRoles.FirstOrDefaultAsync(sr => sr.Id == roleId);

        private async Task<ApplicationUser> FindUserByEmail(string email) =>
            await appDbContext.ApplicationUsers.FirstOrDefaultAsync(u => u.Email.ToLower()!.Equals(email!.ToLower()));

        private async Task<T> AddToDb<T>(T model) 
        {
            var result = appDbContext.Add(model!);
            await appDbContext.SaveChangesAsync();
            return (T)result.Entity;

        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            if (token == null) return new LoginResponse(false, "Model is empty");
            var findToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(rt => rt.Token!.Equals(token.Token));
            if (findToken is null) return new LoginResponse(false, "Refresh Token is required");

            var user = await appDbContext.ApplicationUsers.FirstOrDefaultAsync(u => u.Id == findToken.UserId);
            if (user is null) return new LoginResponse(false, "User not found");

            var userRole = await FindUserRole(user.Id);
            var roleName = await FindRoleName(userRole.RoleId);
            var jwtToken = GenerateToken(user, roleName!.Name!);
            var refreshToken = GenerateRefreshToken();

            var updateRefreshToken = await appDbContext.RefreshTokenInfos.FirstOrDefaultAsync(rt => rt.UserId == user.Id);
            if (updateRefreshToken is null) return new LoginResponse(false, "Refresh Token not found");

            updateRefreshToken.Token = refreshToken;
            await appDbContext.SaveChangesAsync();

            return new LoginResponse(true, "Token refreshed", jwtToken, refreshToken);
        }
    }
}
