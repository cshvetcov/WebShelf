using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Serilog.Events;
using WebShelf.Classes.DC;
using WebShelf.Classes.Security;
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

    // --- Группы безопасности AD ---
    // После считывания конфигурации (мастер-ключ, инициализация домена, проверка
    // сервисной учётной записи): 0) самопроверка каталога ролей — единый источник
    // истины о составе ролей и группах; 1) формирование списка необходимых групп из
    // шаблонов имён — группа доступа Users (шаблон хранится в Domain) и шаблоны
    // ролевых групп из каталога ролей (RoleCatalog, под Гостя группа не создаётся);
    // {InstanceIdShort} заменяется коротким префиксом InstanceId;
    // 2) проверка существования групп и создание отсутствующих от имени сервисной УЗ.
    // При любой ошибке приложение завершается — без необходимых групп оно не работает.
    // После успешного чтения конфигурации домен гарантированно инициализирован
    Domain domain = data.Domain!;

    if (!RoleCatalog.Validate())
    {
        Log.Fatal(
            "Каталог ролей неконсистентен (дубликаты или пустые значения). Приложение останавливается. Class={Class}, Method={Method}",
            "WebShelf.Program", "Main");
        return 1;
    }

    List<string> groupNameTemplates =
    [
        // Группа доступа Users — не роль: шаблон хранится в Domain
        $"WebShelf-{Domain.InstanceIdShortPlaceholder}-{Domain.UsersGroupSuffix}",
        // Шаблоны ролевых групп — по одной на каждую роль каталога (Гость исключён)
        .. RoleCatalog.BuildGroupNameTemplates()
    ];

    if (!domain.FillRequiredGroupsFromTemplates(groupNameTemplates))
    {
        Log.Fatal(
            "Не удалось сформировать список необходимых групп безопасности AD. Приложение останавливается. Class={Class}, Method={Method}",
            "WebShelf.Program", "Main");
        return 1;
    }

    if (!domain.EnsureRequiredGroupsExist())
    {
        Log.Fatal(
            "Не удалось создать необходимые группы безопасности AD. Приложение останавливается. Class={Class}, Method={Method}",
            "WebShelf.Program", "Main");
        return 1;
    }

    // Требование: в системе всегда должен быть минимум один администратор.
    // Проверяется после создания групп: если в группе администраторов нет ни одного
    // участника — предупреждение в лог (запуск не блокируется: группа могла быть
    // только что создана и ждёт первого участника).
    string? adminGroup = domain.GetExpandedGroupName(RoleCatalog.Administrator.GroupSuffix!);
    if (adminGroup is not null)
    {
        List<string>? adminMembers = domain.GetGroupMemberNames(adminGroup);
        if (adminMembers is not { Count: > 0 })
        {
            Log.Warning(
                "В группе администраторов {Group} нет участников — нарушено требование наличия минимум одного администратора. Class={Class}, Method={Method}",
                adminGroup, "WebShelf.Program", "Main");
        }
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

    #region TLS-сертификат для схемы https
    // При https Kestrel обязан получить сертификат явно — без него запуск невозможен.
    // Сертификат загружается в Data при чтении конфигурации (certpath + scertpass/certpass).
    // Явный Listen имеет приоритет над UseUrls — адрес и порт совпадают с listenUrl.
    if (string.Equals(data.Scheme, "https", StringComparison.OrdinalIgnoreCase))
    {
        if (data.TlsCertificate is null)
        {
            Log.Fatal(
                "TLS-сертификат недоступен: прослушивание по https невозможно. Приложение останавливается. Class={Class}, Method={Method}",
                "WebShelf.Program", "Main");
            return 1;
        }

        // Локальная переменная: переносит non-null состояние в замыкание ConfigureKestrel
        X509Certificate2 tlsCertificate = data.TlsCertificate;

        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Any, data.Port!.Value, listenOptions =>
            {
                listenOptions.UseHttps(tlsCertificate);
            });
        });

        Log.Information(
            "TLS-сертификат привязан к Kestrel. Subject={Subject}, NotAfter={NotAfter}. Class={Class}, Method={Method}",
            tlsCertificate.Subject, tlsCertificate.NotAfter, "WebShelf.Program", "Main");
    }
    #endregion

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

    // --- Ролевая модель (варианты 1+2+3) ---
    // Вариант 1: TTL-кэш роли в резолвере (rolettl, по умолчанию 60 с).
    // Вариант 2: фоновый опрос ролевых групп с push-обновлением открытых цепочек
    // (rolepoll, по умолчанию 30 с) — событие идёт через RoleChangeNotifier
    // в scoped-провайдер каждой цепочки.
    // Вариант 3: свежая LDAP-проверка в обход кэша — при входе и критичных операциях.
    // Конструкторы всех сервисов объявлены public (классы internal): контейнер DI
    // находит только public-конструкторы.
    // Источник данных о группах AD для ролевой модели — Domain, инициализированный
    // при чтении конфигурации (тот же экземпляр, что хранится в Data). Без этой
    // регистрации контейнер не собирает RoleResolver и зависимые от него сервисы
    // (провайдер состояния аутентификации, фоновый опрос) — ошибка валидации
    // при builder.Build()
    builder.Services.AddSingleton<IAdGroupSource>(domain);
    builder.Services.AddSingleton(TimeProvider.System);
    builder.Services.AddSingleton(data.RoleCacheOptions!);
    builder.Services.AddSingleton<RoleResolver>();
    builder.Services.AddSingleton<RoleChangeNotifier>();
    builder.Services.AddScoped<AuthenticationStateProvider, AppAuthenticationStateProvider>();
    // AddHostedService одновременно регистрирует службу как singleton,
    // отдельная регистрация не нужна
    builder.Services.AddHostedService<RoleRefreshService>();

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

    // Эндпоинты входа/выхода (POST /account/login, POST /account/logout):
    // маршруты и обработчики — в Classes/Security/AccountEndpoints.cs
    app.MapAccountEndpoints();

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
    // Освобождение пула соединений PostgreSQL и TLS-сертификата до закрытия логов
    data.Database?.Dispose();
    data.TlsCertificate?.Dispose();
    InstanceLock.Release();
    Log.CloseAndFlush();
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
