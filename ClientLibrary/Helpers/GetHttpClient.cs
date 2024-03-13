using BaseLibrary.DTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace ClientLibrary.Helpers
{
    public class GetHttpClient(IHttpClientFactory httpClientFactory, LocalStorageService localStorageService)
    {
        private const string HeaderKey = "Authorization";

        public async Task<HttpClient> GetPrivateHttpClient()
        {
            var client = httpClientFactory.CreateClient("SystemApiClient");
            var token = await localStorageService.GetToken();
           if (string.IsNullOrEmpty(token)) return client;

            var deserialization = Serializations.Deserialize<UserSession>(token);
            if (deserialization == null) return client;
            
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", deserialization.Token);
            return client; 
        }

        public HttpClient GetPublicHttpClient()
        {
            var client = httpClientFactory.CreateClient("SystemApiClient");
            client.DefaultRequestHeaders.Remove(HeaderKey);

            return client;
        }
        
    }
}
