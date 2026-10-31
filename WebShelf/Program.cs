using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;
using Serilog.Events;
using WebShelf.Classes.DC;
using WebShelf.Classes.Service;
using WebShelf.Components;

// Единый шаблон вывода логов: используется и bootstrap-логгером, и логгером хоста
const string LogOutputTemplate =
    "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] [{ThreadId}] {Message:lj}{NewLine}{Exception}";

// Лог последнего запуска (только Debug): перед каждым стартом очищается,
// поэтому содержит лог только текущего запуска
const string LastLogFileName = "Last.log";

#if DEBUG
// Очистка Last.log до создания логгера: sink файла создаётся при конфигурации
// логгера, поэтому удаление должно пройти раньше. До настройки Serilog логировать
// некуда (SilentLogger), поэтому при ошибке удаления старт не блокируется —
// Last.log просто останется с прошлого запуска.
try
{
    string lastLogPath = Path.Combine(AppContext.BaseDirectory, "logs", LastLogFileName);
    if (File.Exists(lastLogPath))
    {
        File.Delete(lastLogPath);
    }
}
catch
{
    // Не блокируем старт, если Last.log занят другим процессом или недоступен
}
#endif

// Ранний bootstrap-логгер (до Build): общая настройка вынесена в ApplySerilogDefaults
Log.Logger = ApplySerilogDefaults(new LoggerConfiguration())
    .CreateLogger();

// Единственный экземпляр хранилища системных данных. Создаётся до сборки хоста:
// схема, порт и домен из Server.conf нужны при конфигурации хоста (UseUrls, cookie).
// Этот же экземпляр ниже регистрируется в DI как singleton.
Data data = new();

try
{
    Log.Information("WebShelf запускается...");

    string version = ThisAssembly.AssemblyInformationalVersion.Split('+')[0];

    string commitShort = ThisAssembly.GitCommitId is { Length: >= 10 } id ? id[..10] : ThisAssembly.GitCommitId ?? "unknown";

    Log.Information(
        "Версия: {Version}, Commit={Commit}. Class={Class}, Method={Method}",
        version,
        commitShort,
        "WebShelf.Program", "Main");

    // Один экземпляр на учётную запись Windows.
    // return (вместо Environment.Exit) гарантирует выполнение finally:
    // освобождение мьютекса и CloseAndFlush — без потери последних сообщений лога.
    if (!InstanceLock.TryAcquire())
    {
        return 1;
    }

    // InstanceId ДО MasterKey и конфигурации
    string? instanceId = EncryptionService.EnsureInstanceId();
    if (string.IsNullOrWhiteSpace(instanceId))
    {
        Log.Fatal(
            "Не удалось обеспечить InstanceId (реестр/DPAPI). Приложение останавливается. Class={Class}, Method={Method}",
            "WebShelf.Program", "Main");
        return 1;
    }

    data.SetInstanceId(instanceId);
    Log.Information(
        "InstanceId готов. Short={Short}. Class={Class}, Method={Method}",
        data.InstanceIdShort, "WebShelf.Program", "Main");

    if (!await data.ReadConfigAsync())
    {
        Log.Fatal("Конфигурация не загружена. Приложение останавливается. Class={Class}, Method={Method}", "WebShelf.Program", "Main");
        return 1;
    }

    // Предупреждение о небезопасной схеме: при http cookie аутентификации
    // передаются без флага Secure и могут быть перехвачены в канале связи.
    if (string.Equals(data.Scheme, "http", StringComparison.OrdinalIgnoreCase))
    {
        Log.Warning(
            "Схема http: cookie аутентификации передаются без защиты Secure. Рекомендуется использовать https. Class={Class}, Method={Method}",
            "WebShelf.Program", "Main");
    }

    WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

    // Единая настройка Serilog для bootstrap-логгера и хоста (без дублирования)
    builder.Host.UseSerilog((context, services, configuration) => ApplySerilogDefaults(configuration));

    // Схема и порт только из Server.conf (независимо от launchSettings.json и профилей http/https)
    string listenUrl = $"{data.Scheme}://0.0.0.0:{data.Port}";
    builder.WebHost.UseUrls(listenUrl);
    Log.Information(
        "Прослушивание {ListenUrl} (Server.conf). Class={Class}, Method={Method}",
        listenUrl, "WebShelf.Program", "Main");

    #region Постоянное хранение ключей Data Protection
    // Ключи Data Protection шифруют билет аутентификационной куки и antiforgery-токены.
    // Без явной настройки при работе службы они могут храниться эфемерно — после
    // рестарта все сессии и токены становятся недействительными (выход всех пользователей).
    // Хранение — рядом с бинарниками (как и логи), защита — DPAPI текущей учётной
    // записи службы: файлы ключей бесполезны при копировании под другой учёткой.
    string keysPath = Path.Combine(AppContext.BaseDirectory, "keys");
    Directory.CreateDirectory(keysPath);
    builder.Services.AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo(keysPath))
        .ProtectKeysWithDpapi();

    Log.Information(
        "Data Protection keys: {KeysPath}. Class={Class}, Method={Method}",
        keysPath, "WebShelf.Program", "Main");
    #endregion

    #region Аутентификация через куки
    bool preferSecure = string.Equals(data.Scheme, "https", StringComparison.OrdinalIgnoreCase);

    builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(options =>
        {
            options.LoginPath = "/entry";
            options.AccessDeniedPath = "/entry";
            options.ExpireTimeSpan = TimeSpan.FromHours(8);
            // Скользящее обновление отключено: при SlidingExpiration=true продление
            // перезаписывает ExpiresUtc билета значением ExpireTimeSpan (8 часов),
            // из-за чего «Запомнить меня» на 14 дней вырождалась в скользящую
            // 8-часовую сессию. Срок жизни билета теперь фиксируется один раз
            // в AuthenticationProperties при входе (см. LoginAsync):
            // rememberMe — 14 календарных дней, обычная сессия — 8 часов.
            options.SlidingExpiration = false;
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

    // Хранилище системных данных (конфигурация уже загружена выше) — singleton в DI
    builder.Services.AddSingleton(data);

    builder.Services.AddSingleton<LoginGuard>();

    builder.Services.AddRazorComponents().AddInteractiveServerComponents();

    WebApplication app = builder.Build();

    app.UseSerilogRequestLogging();

    // Заголовки безопасности (CSP, X-Frame-Options и др.) добавляются во все ответы
    app.UseWebShelfSecurityHeaders();

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

    app.UseAuthentication();
    app.UseAuthorization();
    app.UseAntiforgery();

    app.MapStaticAssets();
    app.MapPost("/account/login", LoginAsync);
    // Выход только по POST с antiforgery-током — защита от logout-CSRF
    app.MapPost("/account/logout", LogoutAsync);
    app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

    app.Run();
    return 0;
}
catch (Exception ex)
{
    Log.Fatal(ex, "Исключение в {Class}.{Method}", "WebShelf.Program", "Main");
    throw;
}
finally
{
    // Освобождение пула соединений PostgreSQL до закрытия логов
    data.Database?.Dispose();
    InstanceLock.Release();
    Log.CloseAndFlush();
}

/// <summary>
/// Обработчик POST /account/login — CSRF-проверка, защита от перебора, проверка AD и выдача cookie.
/// </summary>
static async Task<IResult> LoginAsync(
    HttpContext context,
    IAntiforgery antiforgery,
    LoginGuard loginGuard,
    Data data)
{
    const string className = "WebShelf.Program";
    const string method = nameof(LoginAsync);

    try
    {
        // --- CSRF ---
        // Antiforgery-middleware (UseAntiforgery) сама отклоняет form-POST без
        // валидного токена (400). Ручная проверка ниже — второй контур: она срабатывает
        // для запросов, которые middleware не проверяет (нестандартный Content-Type),
        // и возвращает дружелюбный редирект на форму входа вместо голого 400.
        try
        {
            await antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException ex)
        {
            Log.Warning(ex, "Неверный antiforgery-токен при входе. Class={Class}, Method={Method}", className, method);
            return Results.Redirect("/entry?error=invalid");
        }

        IFormCollection form = await context.Request.ReadFormAsync();
        string? username = form["username"];
        string? password = form["password"];
        bool rememberMe = form["rememberMe"] == "true";

        string clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // Канонизация имени до обращения к LoginGuard: 'ivanov', 'DOMAIN\ivanov' и
        // 'ivanov@domain' должны попадать в один и тот же ключ учёта попыток.
        // Без канонизации перебор форматов имени обходит per-account блокировку:
        // каждый формат заводит в LoginGuard отдельный счётчик.
        // Доменная часть известна только после загрузки конфигурации (data.Domain),
        // поэтому при её отсутствии канонизация невозможна — передаётся null и
        // попытки учитываются только по IP-ключу.
        string? userKey = string.IsNullOrWhiteSpace(username) || data.Domain is null
            ? null
            : Domain.NormalizeUserName(username, data.Domain.Name);

        // --- Brute-force: уже заблокирован? ---
        if (loginGuard.IsLocked(clientIp, userKey, out int remainBefore))
        {
            Log.Warning(
                "Попытка входа во время блокировки. Ip={Ip}, RemainSec={Sec}. Class={Class}, Method={Method}",
                clientIp, remainBefore, className, method);
            return Results.Redirect($"/entry?error=locked&retry={remainBefore}");
        }

        // userKey == null при непустом имени — формат не распознан (нет домена или
        // некорректный ввод): AD-проверка всё равно бы не прошла, фиксируем как отказ.
        if (string.IsNullOrWhiteSpace(username) || password is null || data.Domain is null || userKey is null)
        {
            int lockedSec = loginGuard.RecordFailure(clientIp, null);
            if (lockedSec > 0)
                return Results.Redirect($"/entry?error=locked&retry={lockedSec}");
            return Results.Redirect("/entry?error=invalid");
        }

        bool isValid = data.Domain.ValidateAdCredentials(userKey, password);
        if (!isValid)
        {
            int lockedSec = loginGuard.RecordFailure(clientIp, userKey);
            // Реальное имя учётной записи в лог не попадает
            Log.Warning(
                "Неудачная попытка входа. Ip={Ip}, LockedSec={Sec}. Class={Class}, Method={Method}",
                clientIp, lockedSec, className, method);

            if (lockedSec > 0)
                return Results.Redirect($"/entry?error=locked&retry={lockedSec}");
            return Results.Redirect("/entry?error=invalid");
        }

        loginGuard.RecordSuccess(clientIp, userKey);

        // В claims уходит канонический sAMAccountName без доменной части —
        // независимо от того, в каком формате пользователь ввёл логин.
        string samAccountName = userKey[..userKey.IndexOf('@')];

        List<Claim> claims = new List<Claim>
        {
            new(ClaimTypes.Name, samAccountName),
            new(ClaimTypes.NameIdentifier, samAccountName)
        };

        ClaimsIdentity identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        ClaimsPrincipal principal = new ClaimsPrincipal(identity);

        AuthenticationProperties props = new AuthenticationProperties
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

        // Возврат на исходную страницу: cookie-аутентификация при [Authorize]-редиректе
        // кладёт исходный путь в query ReturnUrl (/entry?ReturnUrl=...), форма входа
        // передаёт его скрытым полем. Внешние (нелокальные) адреса отбрасываются —
        // защита от open redirect; реальное имя учётной записи в лог не попадает.
        string? returnUrl = form["returnUrl"];
        if (!string.IsNullOrEmpty(returnUrl) && IsLocalUrl(returnUrl))
        {
            Log.Information(
                "Вход выполнен, переход по исходному пути. Class={Class}, Method={Method}",
                className, method);
            return Results.Redirect(returnUrl);
        }

        Log.Information(
            "Вход выполнен. Class={Class}, Method={Method}",
            className, method);
        return Results.Redirect("/");
    }
    catch (Exception ex)
    {
        Log.Error(ex, "Исключение в {Class}.{Method}", className, method);
        return Results.Redirect("/entry?error=server");
    }
}

/// <summary>
/// Проверяет, что URL локальный (относительный путь внутри приложения).
/// Каноническая реализация ASP.NET Core: допустимы '/', '/путь', при этом
/// протокол-относительные '//host' и '/\host' локальными не считаются —
/// защита от open redirect при обработке ReturnUrl.
/// </summary>
static bool IsLocalUrl(string? url)
{
    if (string.IsNullOrEmpty(url))
    {
        return false;
    }

    return url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'));
}

/// <summary>
/// Обработчик POST /account/logout — CSRF-проверка, выход и очистка cookie.
/// Выход выполняется только POST-запросом с валидным antiforgery-током —
/// защита от logout-CSRF (автоматический GET-запрос со стороннего сайта).
/// </summary>
static async Task<IResult> LogoutAsync(
    HttpContext context,
    IAntiforgery antiforgery)
{
    const string className = "WebShelf.Program";
    const string method = nameof(LogoutAsync);

    try
    {
        // --- CSRF ---
        try
        {
            await antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException ex)
        {
            Log.Warning(ex, "Неверный antiforgery-токен при выходе. Class={Class}, Method={Method}", className, method);
            return Results.BadRequest();
        }

        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        Log.Information("Выход выполнен. Class={Class}, Method={Method}", className, method);

        // Fetch (XHR) с redirect:manual — 204, cookie уже сброшен, клиент сам идёт на /entry.
        // Обычный POST-переход браузера — 302 на /entry.
        string accept = context.Request.Headers.Accept.ToString();
        bool isFetch = accept.Contains("application/json", StringComparison.OrdinalIgnoreCase)
                       || string.Equals(context.Request.Headers["X-Requested-With"], "XMLHttpRequest", StringComparison.OrdinalIgnoreCase)
                       || string.Equals(context.Request.Headers["Sec-Fetch-Mode"], "cors", StringComparison.OrdinalIgnoreCase);

        if (isFetch)
        {
            return Results.NoContent();
        }

        return Results.Redirect("/entry");
    }
    catch (Exception ex)
    {
        Log.Error(ex, "Исключение в {Class}.{Method}", className, method);
        return Results.Redirect("/entry");
    }
}

/// <summary>
/// Применяет единую настройку Serilog: уровни, overrides, enrichers и sinks.
/// Используется и для раннего bootstrap-логгера, и для логгера хоста.
/// </summary>
static LoggerConfiguration ApplySerilogDefaults(LoggerConfiguration configuration)
{
    const string className = "WebShelf.Program";
    const string method = nameof(ApplySerilogDefaults);

    try
    {
        LoggerConfiguration config = configuration
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
                outputTemplate: LogOutputTemplate);

#if DEBUG
        // Дублируем лог в Last.log: файл очищается перед каждым Debug-стартом,
        // поэтому содержит только текущий запуск. shared: true обязателен —
        // bootstrap-логгер и логгер хоста пишут в один файл одновременно.
        config = config.WriteTo.File(
            path: Path.Combine(AppContext.BaseDirectory, "logs", LastLogFileName),
            shared: true,
            outputTemplate: LogOutputTemplate);
#endif

        return config;
    }
    catch (Exception ex)
    {
        Log.Error(ex, "Исключение в {Class}.{Method}", className, method);
        throw;
    }
}