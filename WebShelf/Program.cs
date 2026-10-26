using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using Serilog.Events;
using WebShelf.Classes.Service;
using WebShelf.Components;

// Ранний bootstrap-логгер (до Build)
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.AspNetCore.Components", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .Enrich.WithEnvironmentName()
    .Enrich.WithThreadId()
    .WriteTo.Debug()
    .WriteTo.File(
        path: Path.Combine(AppContext.BaseDirectory, "logs", "webshelf-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        shared: true,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] [{ThreadId}] {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

try
{
    Log.Information("WebShelf запускается...");

    if (!Data.ReadConfig())
    {
        Log.Fatal("Конфигурация не загружена. Приложение останавливается. Class={Class}, Method={Method}", "WebShelf.Program", "Main");
        Environment.Exit(1);
    }

    WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

    // Схема и порт только из Server.conf (независимо от launchSettings.json и профилей http/https)
    string listenUrl = $"{Data.Scheme}://0.0.0.0:{Data.Port}";
    builder.WebHost.UseUrls(listenUrl);
    Log.Information(
        "Прослушивание {ListenUrl} (Server.conf). Class={Class}, Method={Method}",
        listenUrl, "WebShelf.Program", "Main");

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

    WebApplication app = builder.Build();

    app.MapPost("/account/login", LoginAsync);
    app.MapGet("/account/logout", LogoutAsync);

    app.UseAuthentication();
    app.UseAuthorization();

    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Error", createScopeForErrors: true);
        app.UseHsts();
    }

    app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);

    // Редирект на HTTPS только если в Server.conf указана схема https
    if (string.Equals(Data.Scheme, "https", StringComparison.OrdinalIgnoreCase))
    {
        app.UseHttpsRedirection();
    }

    app.UseAntiforgery();

    app.MapStaticAssets();
    app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Исключение в {Class}.{Method}", "WebShelf.Program", "Main");
    throw;
}
finally
{
    Log.CloseAndFlush();
}

/// <summary>
/// Обработчик POST /account/login — проверка учётных данных AD и выдача cookie.
/// </summary>
static async Task<IResult> LoginAsync(HttpContext context, IConfiguration config)
{
    try
    {
        var form = await context.Request.ReadFormAsync();
        string? username = form["username"];
        string? password = form["password"];
        bool rememberMe = form["rememberMe"] == "true";

        if (string.IsNullOrWhiteSpace(username) || password is null || Data.Domain is null)
            return Results.Redirect("/?error=invalid");

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
    catch (Exception ex)
    {
        Log.Error(ex, "Исключение в {Class}.{Method}", "WebShelf.Program", nameof(LoginAsync));
        return Results.Redirect("/?error=server");
    }
}

/// <summary>
/// Обработчик GET /account/logout — выход и очистка cookie.
/// </summary>
static async Task<IResult> LogoutAsync(HttpContext context)
{
    try
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Results.Redirect("/");
    }
    catch (Exception ex)
    {
        Log.Error(ex, "Исключение в {Class}.{Method}", "WebShelf.Program", nameof(LogoutAsync));
        return Results.Redirect("/");
    }
}