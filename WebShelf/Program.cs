using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using WebShelf.Classes.Service;
using WebShelf.Components;

Data.ReadConfig();

var builder = WebApplication.CreateBuilder(args);

#region Аутентификация через куки
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/";
        options.AccessDeniedPath = "/";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
        options.Cookie.Name = "WebShelf.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });

builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();
#endregion

builder.Services.AddRazorComponents().AddInteractiveServerComponents();

var app = builder.Build();

app.MapPost("/account/login", async (HttpContext context, IConfiguration config) =>
{
    var form = await context.Request.ReadFormAsync();
    string? username = form["username"];
    string? password = form["password"];
    bool rememberMe = form["rememberMe"] == "true";

    if (string.IsNullOrWhiteSpace(username) || password is null || Data.Domain is null)
        return Results.Redirect("/?error=invalid");

    try
    {
        bool isValid = Data.Domain.ValidateAdCredentials(username.Trim(), password);
        if (!isValid)
            return Results.Redirect("/?error=invalid");

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username.Trim()),
            new(ClaimTypes.NameIdentifier, username.Trim())
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        var props = new AuthenticationProperties
        {
            IsPersistent = rememberMe,
            ExpiresUtc = rememberMe
                ? DateTimeOffset.UtcNow.AddDays(14)
                : DateTimeOffset.UtcNow.AddHours(8)
        };

        await context.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            props);

        return Results.Redirect("/");
    }
    catch
    {
        return Results.Redirect("/?error=server");
    }
});

app.MapGet("/account/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
});


app.UseAuthentication();
app.UseAuthorization();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.Run();

