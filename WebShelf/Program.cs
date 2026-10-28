using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Antiforgery;
using System.Security.Claims;
using Serilog.Events;
using WebShelf.Classes.Service;
using WebShelf.Components;

const string LogOutputTemplate =
    "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] [{ThreadId}] {Message:lj}{NewLine}{Exception}";

string logsDir = Path.Combine(AppContext.BaseDirectory, "logs");
Directory.CreateDirectory(logsDir);

// В Debug-сборке перед каждым запуском очищаем Last.log,
// чтобы файл содержал только лог текущего (последнего) запуска.
#if DEBUG
string lastLogPath = Path.Combine(logsDir, "Last.log");
try
{
    if (File.Exists(lastLogPath)) File.Delete(lastLogPath);
}
catch
{
    // Не блокируем старт, если не удалось удалить старый Last.log
}
#endif

// Ранний bootstrap-логгер (до Build)
LoggerConfiguration bootstrapConfig = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.AspNetCore.Components", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .Enrich.WithEnvironmentName()
    .Enrich.WithThreadId()
    .WriteTo.Debug()
    .WriteTo.File(
        path: Path.Combine(logsDir, "webshelf-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        shared: true,
        outputTemplate: LogOutputTemplate);

#if DEBUG
bootstrapConfig = bootstrapConfig.WriteTo.File(
    path: lastLogPath,
    shared: true,
    outputTemplate: LogOutputTemplate);
#endif

Log.Logger = bootstrapConfig.CreateLogger();

try
{
    Log.Information("WebShelf запускается...");

    if (EncryptionService.EnsureMasterKey() == null)
    {
        Log.Fatal("Не удалось создать или загрузить мастер-ключ. Приложение останавливается. Class={Class}, Method={Method}", "WebShelf.Program", "Main");
        Environment.Exit(1);
    }

    if (!Data.ReadConfig())
    {
        Log.Fatal("Конфигурация не загружена. Приложение останавливается. Class={Class}, Method={Method}", "WebShelf.Program", "Main");
        Environment.Exit(1);
    }

    WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog((context, services, configuration) =>
    {
        configuration
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.AspNetCore.Components", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.WithEnvironmentName()
            .Enrich.WithThreadId()
            .WriteTo.Debug()
            .WriteTo.File(
                path: Path.Combine(logsDir, "webshelf-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 30,
                shared: true,
                outputTemplate: LogOutputTemplate);

#if DEBUG
        configuration.WriteTo.File(
            path: lastLogPath,
            shared: true,
            outputTemplate: LogOutputTemplate);
#endif
    });

    // Схема и порт только из Server.conf (независимо от launchSettings.json и профилей http/https)
    string listenUrl = $"{Data.Scheme}://0.0.0.0:{Data.Port}";
    builder.WebHost.UseUrls(listenUrl);
    Log.Information(
        "Прослушивание {ListenUrl} (Server.conf). Class={Class}, Method={Method}",
        listenUrl, "WebShelf.Program", "Main");

    #region Аутентификация через куки
    bool preferSecure = string.Equals(Data.Scheme, "https", StringComparison.OrdinalIgnoreCase);

    builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(options =>
        {
            options.LoginPath = "/entry";
            options.AccessDeniedPath = "/entry";
            options.ExpireTimeSpan = TimeSpan.FromHours(8);
            options.SlidingExpiration = true;
            options.Cookie.Name = "WebShelf.Auth";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = preferSecure
                ? CookieSecurePolicy.Always
                : CookieSecurePolicy.SameAsRequest;
            options.Cookie.SameSite = SameSiteMode.Lax;
        });

    builder.Services.AddAuthorization();
    builder.Services.AddCascadingAuthenticationState();
    builder.Services.AddHttpContextAccessor();
    #endregion

    // Antiforgery (CSRF) + защита от перебора паролей
    builder.Services.AddAntiforgery(options =>
    {
        options.HeaderName = "RequestVerificationToken";
        options.Cookie.Name = "WebShelf.Antiforgery";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = preferSecure
            ? CookieSecurePolicy.Always
            : CookieSecurePolicy.SameAsRequest;
        options.Cookie.SameSite = SameSiteMode.Strict;
    });

    builder.Services.AddSingleton<LoginGuard>();

    builder.Services.AddRazorComponents().AddInteractiveServerComponents();

    WebApplication app = builder.Build();

    app.UseSerilogRequestLogging();

    app.UseAuthentication();
    app.UseAuthorization();

    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Error", createScopeForErrors: true);
        app.UseHsts();
    }

    app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);

    // Редирект на HTTPS только если в Server.conf указана схема https
    if (preferSecure)
    {
        app.UseHttpsRedirection();
    }

    app.UseAntiforgery();

    app.MapPost("/account/login", LoginAsync);
    app.MapGet("/account/logout", LogoutAsync);

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
/// Обработчик POST /account/login — CSRF-проверка, защита от перебора, проверка AD и выдача cookie.
/// </summary>
static async Task<IResult> LoginAsync(
    HttpContext context,
    IAntiforgery antiforgery,
    LoginGuard loginGuard)
{
    const string className = "WebShelf.Program";
    const string method = nameof(LoginAsync);

    try
    {
        // --- CSRF ---
        try
        {
            await antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException ex)
        {
            Log.Warning(ex, "Неверный antiforgery-токен при входе. Class={Class}, Method={Method}", className, method);
            return Results.Redirect("/entry?error=invalid");
        }

        var form = await context.Request.ReadFormAsync();
        string? username = form["username"];
        string? password = form["password"];
        bool rememberMe = form["rememberMe"] == "true";

        string clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        string userKey = string.IsNullOrWhiteSpace(username) ? string.Empty : username.Trim();

        // --- Brute-force: уже заблокирован? ---
        if (loginGuard.IsLocked(clientIp, userKey, out int remainBefore))
        {
            Log.Warning(
                "Попытка входа во время блокировки. Ip={Ip}, User={User}, RemainSec={Sec}. Class={Class}, Method={Method}",
                clientIp, "UserAccount", remainBefore, className, method);
            return Results.Redirect($"/entry?error=locked&retry={remainBefore}");
        }

        if (string.IsNullOrWhiteSpace(username) || password is null || Data.Domain is null)
        {
            int lockedSec = loginGuard.RecordFailure(clientIp, userKey);
            if (lockedSec > 0)
                return Results.Redirect($"/entry?error=locked&retry={lockedSec}");
            return Results.Redirect("/entry?error=invalid");
        }

        bool isValid = Data.Domain.ValidateAdCredentials(username.Trim(), password);
        if (!isValid)
        {
            int lockedSec = loginGuard.RecordFailure(clientIp, userKey);
            Log.Warning(
                "Неудачная попытка входа. Ip={Ip}, User={User}, LockedSec={Sec}. Class={Class}, Method={Method}",
                clientIp, "UserAccount", lockedSec, className, method);

            if (lockedSec > 0)
                return Results.Redirect($"/entry?error=locked&retry={lockedSec}");
            return Results.Redirect("/entry?error=invalid");
        }

        loginGuard.RecordSuccess(clientIp, userKey);

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
        Log.Error(ex, "Исключение в {Class}.{Method}", className, method);
        return Results.Redirect("/entry?error=server");
    }
}

/// <summary>
/// Обработчик GET /account/logout — выход, очистка cookie и переход на страницу входа.
/// Использует Response.Redirect (302), а не IResult, чтобы редирект гарантированно уходил в браузер.
/// </summary>
static async Task LogoutAsync(HttpContext context)
{
    const string className = "WebShelf.Program";
    const string method = nameof(LogoutAsync);

    try
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // Явно гасим auth-cookie (Path/SameSite как при выдаче)
        context.Response.Cookies.Delete(
            "WebShelf.Auth",
            new CookieOptions
            {
                Path = "/",
                HttpOnly = true,
                Secure = context.Request.IsHttps,
                SameSite = SameSiteMode.Lax
            });

        context.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        context.Response.Headers.Pragma = "no-cache";

        Log.Information("Выход выполнен, редирект на /entry. Class={Class}, Method={Method}", className, method);
        context.Response.Redirect("/entry", permanent: false);
    }
    catch (Exception ex)
    {
        Log.Error(ex, "Исключение в {Class}.{Method}", className, method);
        context.Response.Redirect("/entry", permanent: false);
    }
}