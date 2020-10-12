using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Client
{
    public class Startup
    {
        private static ConcurrentDictionary<string, object> tokenRefreshing = new ConcurrentDictionary<string, object>();

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpClient();

            services.AddControllersWithViews();

            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = "cookie";
                    options.DefaultChallengeScheme = "oidc";
                })
                .AddCookie("cookie", options =>
                {
                    options.SlidingExpiration = false;
                    options.Events = new CookieAuthenticationEvents()
                    {
                        OnSigningIn = context =>
                        {
                            context.Properties.IsPersistent = true;
                            context.Properties.ExpiresUtc =
                                DateTime.Parse(context.Properties.Items[".Token.expires_at"])
                                .ToUniversalTime();
                            return Task.CompletedTask;
                        },
                        OnValidatePrincipal = async context =>
                        {
                            var lifetime = context.Properties.ExpiresUtc.Value.Subtract(context.Properties.IssuedUtc.Value);
                            if (DateTime.UtcNow <= context.Properties.IssuedUtc.Value + (lifetime / 2))
                            {
                                return;
                            }

                            var oldAccessToken = context.Properties.Items[".Token.access_token"];
                            if (!tokenRefreshing.TryAdd(oldAccessToken, new object()))
                            {
                                // someone is already refreshing that cookie
                                return;
                            }

                            try
                            {
                                // we have passed the midpoint of the cookie's lifetime, refresh

                                var oldRefreshToken = context.Properties.Items[".Token.refresh_token"];
                                var requestedAtUtc = DateTime.Now;
                                (bool success, bool invalidGrant, string idToken, string accesToken, string refreshToken, int expires, string tokenType) =
                                    await GetAccessTokenAsync(
                                        context.HttpContext,
                                        $"https://localhost:5000/connect/token",
                                        "oidcClient",
                                        "SuperSecretPassword",
                                        oldRefreshToken,
                                        context.HttpContext.RequestAborted);

                                if (success)
                                {
                                    var expiresAtUtc = requestedAtUtc.AddSeconds(expires);
                                    context.Properties.Items[".Token.id_token"] = idToken;
                                    context.Properties.Items[".Token.access_token"] = accesToken;
                                    context.Properties.Items[".Token.refresh_token"] = refreshToken ?? oldRefreshToken;
                                    context.Properties.Items[".Token.expires_at"] = expiresAtUtc.ToString("yyyy-MM-ddTHH\\:mm\\:ss.fffffffzzz");
                                    context.Properties.Items[".Token.token_type"] = tokenType;

                                    context.Properties.IsPersistent = true;
                                    context.Properties.IssuedUtc = requestedAtUtc;
                                    context.Properties.ExpiresUtc = expiresAtUtc;

                                    context.ShouldRenew = true;
                                }
                                else if (invalidGrant)
                                {
                                    context.RejectPrincipal();
                                }
                            }
                            finally
                            {
                                // ensure that the lock is released
                                // 1. to stop the dictionary from growing indefinitely
                                // 2. to allow a retry if the refresh fails for whatever reason 
                                tokenRefreshing.Remove(oldAccessToken, out _);
                            }
                        }
                    };
                })
                .AddOpenIdConnect("oidc", options =>
                {
                    options.Authority = "https://localhost:5000";
                    options.ClientId = "oidcClient";
                    options.ClientSecret = "SuperSecretPassword";

                    options.ResponseType = "code";
                    options.UsePkce = true;
                    options.ResponseMode = "query";

                    // options.CallbackPath = "/signin-oidc"; // default redirect URI
                    
                    // options.Scope.Add("oidc"); // default scope
                    // options.Scope.Add("profile"); // default scope
                    options.Scope.Add("api1.read");
                    options.Scope.Add("offline_access");
                    options.SaveTokens = true;

                    options.UseTokenLifetime = false;
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();
            app.UseHttpsRedirection();

            app.UseStaticFiles();
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
        }

        private static async Task<(bool success, bool invalidGrant, string idToken, string accesToken, string refreshToken, int expires, string tokenType)> GetAccessTokenAsync(
            HttpContext httpContext,
            string url,
            string clientId,
            string clientSecret,
            string refreshToken,
            CancellationToken ct)
        {
            using var scope = httpContext.RequestServices.CreateScope();
            using var httpClient = scope.ServiceProvider.GetRequiredService<IHttpClientFactory>().CreateClient();
            var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new FormUrlEncodedContent(
                    new Dictionary<string, string>()
                    {
                        { "grant_type", "refresh_token" },
                        { "client_id", clientId },
                        { "client_secret", clientSecret },
                        { "refresh_token", refreshToken },
                    })
            };

            var resp = await httpClient.SendAsync(req, ct);

            if (!resp.IsSuccessStatusCode &&
                resp.StatusCode != HttpStatusCode.BadRequest)
            {
                return (success: false, invalidGrant: false, idToken: null, accesToken: null, refreshToken: null, expires: 0, tokenType: null);
            }

            var respStream = await resp.Content.ReadAsStreamAsync();
            var json = await JsonSerializer.DeserializeAsync<JsonElement>(respStream);
            
            if (resp.StatusCode == HttpStatusCode.BadRequest &&
                TryGetString(json, "error") == "invalid_grant")
            {
                return (success: false, invalidGrant: true, idToken: null, accesToken: null, refreshToken: null, expires: 0, tokenType: null);
            }

            string idt = TryGetString(json, "id_token");
            string at = TryGetString(json, "access_token");
            string rt = TryGetString(json, "refresh_token");
            int exp = TryGetInt(json, "expires") ?? 0;
            string tt = TryGetString(json, "token_type");

            return (success: true, invalidGrant: false, idToken: idt, accesToken: at, refreshToken: rt, expires: exp, tokenType: tt);
        }

        private static string TryGetString(JsonElement element, string propertyName)
            => element.TryGetProperty(propertyName, out var value)
                ? value.GetString()
                : null;

        private static int? TryGetInt(JsonElement element, string propertyName)
            => element.TryGetProperty(propertyName, out var value)
                ? value.GetInt32()
                : (int?)null;
    }
}
