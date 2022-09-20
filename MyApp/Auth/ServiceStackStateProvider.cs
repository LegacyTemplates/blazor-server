using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.Extensions.Logging;
using ServiceStack;
using ServiceStack.Blazor;

namespace MyApp.Auth;

public static class ClaimTypesExt
{
    public const string Picture = "picture";
}

public class ServiceStackStateProvider : AuthenticationStateProvider
{
    private ApiResult<AuthenticateResponse> authApi = new();
    private readonly JsonApiClient client;
    private ProtectedLocalStorage protectedLocalStorage;
    private bool hasInit = false;

    ILogger<ServiceStackStateProvider> Log { get; }

    public ServiceStackStateProvider(JsonApiClient client, ILogger<ServiceStackStateProvider> log, ProtectedLocalStorage protectedLocalStorage)
    {
        this.client = client;
        this.Log = log;
        this.protectedLocalStorage = protectedLocalStorage;
    }

    private async Task Init()
    {

        var accessToken = await RecoverAccessToken();
        if(accessToken != null)
        {
            client.BearerToken = accessToken;
            client.GetHttpClient().DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }
        var refreshToken = await RecoverRefreshToken();
        if(refreshToken != null)
            client.RefreshToken = refreshToken;
        hasInit = true;
    }

    private async Task<string?> RecoverAccessToken()
    {
        ProtectedBrowserStorageResult<string> val = await protectedLocalStorage.GetAsync<string>(Keywords.TokenCookie);
        return val.Value;
    }

    private async Task<string?> RecoverRefreshToken()
    {
        ProtectedBrowserStorageResult<string> val = await protectedLocalStorage.GetAsync<string>(Keywords.RefreshTokenCookie);
        return val.Value;
    }

    private async Task ClearLocalTokenStorage()
    {
        await protectedLocalStorage.DeleteAsync(Keywords.TokenCookie);
        await protectedLocalStorage.DeleteAsync(Keywords.RefreshTokenCookie);
    }

    public AuthenticateResponse? AuthUser => authApi.Response;
    public bool IsAuthenticated => authApi.Response != null;

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            if (!hasInit)
                await Init();

            var authResponse = authApi.Response;
            if (authResponse == null)
            {
                Log.LogInformation("Checking server /auth for authentication");
                var authApi = await client.ApiAsync(new Authenticate());
                authResponse = authApi.Response;
            }
            
            if (authResponse is null)
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));

            List<Claim> claims = new()
            {
                new Claim(ClaimTypes.NameIdentifier, authResponse.UserId),
                new Claim(ClaimTypes.Name, authResponse.DisplayName),
                new Claim(ClaimTypes.Email, authResponse.UserName),
                new Claim(ClaimTypesExt.Picture, authResponse.ProfileUrl),
            };

            // Add all App Roles to Admin Users to use [Authorize(Roles)]
            var isAdmin = authResponse.Roles.FirstOrDefault(x => x == AppRoles.Admin);
            var roles = isAdmin != null
                ? authResponse.Roles.Union(AppRoles.All).Distinct()
                : authResponse.Roles;
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            foreach (var permission in authResponse.Permissions)
            {
                claims.Add(new Claim(ClaimUtils.PermissionType, permission));
            }

            var identity = new ClaimsIdentity(claims, ClaimUtils.AuthenticationType);
            return new AuthenticationState(new ClaimsPrincipal(identity));
        }
        catch (Exception ex)
        {
            Log.LogError(ex, "SignIn failed");
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }
    }

    public async Task LogoutIfAuthenticatedAsync()
    {
        var authState = await GetAuthenticationStateAsync();
        if (authState.User.Identity?.IsAuthenticated == true)
            await LogoutAsync();
    }

    public async Task<ApiResult<AuthenticateResponse>> LogoutAsync()
    {
        var logoutResult = await client.ApiAsync(new Authenticate { provider = "logout" });
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        await ClearLocalTokenStorage();
        authApi.ClearErrors();
        return logoutResult;
    }

    public Task<ApiResult<AuthenticateResponse>> SignInAsync(ApiResult<AuthenticateResponse> api)
    {
        authApi = api;
        if (authApi.Succeeded)
        {
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
        return Task.FromResult(authApi);
    }

    public Task<ApiResult<AuthenticateResponse>> SignInAsync(AuthenticateResponse authResponse) =>
        SignInAsync(ApiResult.Create(authResponse));

    // Can SignInAsync with RegisterResponse when Register.AutoLogin = true
    public Task<ApiResult<AuthenticateResponse>> SignInAsync(RegisterResponse registerResponse) =>
        SignInAsync(ApiResult.Create(registerResponse.ToAuthenticateResponse()));

    public async Task<ApiResult<AuthenticateResponse>> LoginAsync(string email, string password)
    {
        var authResult = await SignInAsync(await client.ApiAsync(new Authenticate
        {
            provider = "credentials",
            Password = password,
            UserName = email,
        }));

        if(authResult.Succeeded && authResult.Response != null)
        {
            await protectedLocalStorage.SetAsync(Keywords.TokenCookie, authResult.Response.BearerToken);
            await protectedLocalStorage.SetAsync(Keywords.RefreshTokenCookie, authResult.Response.RefreshToken);
            await Init();
        }
        
        return authResult;
    }
}
