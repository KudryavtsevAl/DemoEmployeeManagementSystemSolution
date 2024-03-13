using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Components.Authorization;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace ClientLibrary.Helpers
{
    public class CustomAuthenticationStateProvider(LocalStorageService localStorageService) : AuthenticationStateProvider
    {
        private readonly ClaimsPrincipal _anonymous = new (new ClaimsIdentity());
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var stringToken = await localStorageService.GetToken();
            if (string.IsNullOrEmpty(stringToken)) return await Task.FromResult(new AuthenticationState(_anonymous));

            var desirialisedToken = Serializations.Deserialize<UserSession>(stringToken);
            if (desirialisedToken == null) return await Task.FromResult(new AuthenticationState(_anonymous));

            var getUserClaims = DecryptToken(desirialisedToken.Token!);
            if(getUserClaims is null) return await Task.FromResult(new AuthenticationState(_anonymous));

            var claimsPrincipal = SetClaimPrincipal(getUserClaims);


            return await Task.FromResult(new AuthenticationState(claimsPrincipal));
        }

        
        public async Task UpdateAuthenticationStateAsync(UserSession userSession)
        {
            var claimsPrincipal = new ClaimsPrincipal();

            if (userSession.Token is not null || userSession.RefreshToken is not null) 
            {
                var serializedSession = Serializations.Serialize(userSession);
                await localStorageService.SetToken(serializedSession);
                var userClaims = DecryptToken(userSession.Token!);
                claimsPrincipal = SetClaimPrincipal(userClaims);

            }
            else
            {
                await localStorageService.RemoveToken();
            };

            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }

        private static CustomUserClaims DecryptToken(string jwtToken)
        {
            if (string.IsNullOrEmpty(jwtToken)) return new CustomUserClaims();
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwtToken);

            var id = token.Claims.FirstOrDefault(ct => ct.Type == ClaimTypes.NameIdentifier)?.Value;
            var name = token.Claims.FirstOrDefault(ct => ct.Type == ClaimTypes.Name)?.Value;
            var email = token.Claims.FirstOrDefault(ct => ct.Type == ClaimTypes.Email)?.Value;
            var role = token.Claims.FirstOrDefault(ct => ct.Type == ClaimTypes.Role)?.Value;
            return new CustomUserClaims(id!, name!, email!, role!);
        }

        private static ClaimsPrincipal SetClaimPrincipal(CustomUserClaims claims)
        {
            if (claims.Email is null) return new ClaimsPrincipal();

            var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, claims.Id),
                new Claim(ClaimTypes.Name, claims.Name),
                new Claim(ClaimTypes.Email, claims.Email),
                new Claim(ClaimTypes.Role, claims.Role)
            ], "JwtAuth");

            return new ClaimsPrincipal(identity);
        }
    }
}
