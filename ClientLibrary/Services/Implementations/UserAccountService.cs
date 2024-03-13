using BaseLibrary.DTOs;
using BaseLibrary.Responses;
using ClientLibrary.Helpers;
using ClientLibrary.Services.Contracts;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Json;

namespace ClientLibrary.Services.Implementations
{
    public class UserAccountService(GetHttpClient httpClient) : IUserAccountService
    {
        public const string AuthUrl = "api/auth";
        public async Task<GeneralResponse> CreateAsync([NotNull]Register user)
        {
            var client = httpClient.GetPublicHttpClient();
            var result = await client.PostAsJsonAsync($"{AuthUrl}/register", user);
            if (!result.IsSuccessStatusCode) return new GeneralResponse(false, "Authorization error");

            return await result.Content.ReadFromJsonAsync<GeneralResponse>();
        }
        public async Task<LoginResponse> SignInAsync(Login user)
        {
            var client = httpClient.GetPublicHttpClient();
            var result = await client.PostAsJsonAsync($"{AuthUrl}/login", user);
            if (!result.IsSuccessStatusCode) return new LoginResponse(false, "Login error");

            return await result.Content.ReadFromJsonAsync<LoginResponse>();
        }


        public Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            throw new NotImplementedException();
        }

        public async Task<WeatherForecast[]> GetWeatherForecast()
        {
            var client = httpClient.GetPublicHttpClient();
            var result = await client.GetFromJsonAsync<WeatherForecast[]>("api/weatherforecast");

            return result!;
        }
    }
}
