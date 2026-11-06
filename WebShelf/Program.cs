using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.DataProtection;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;
using Serilog.Events;
using WebShelf.Classes.Crypto;
using WebShelf.Classes.DC;
using WebShelf.Classes.DB;
using WebShelf.Classes.Security;
using WebShelf.Classes.Service;
using WebShelf.Components;

// Единый шаблон вывода логов: используется и bootstrap-логгером, и логгером хоста
const string LogOutputTemplate =
    "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] [{ThreadId}] {Message:lj}{NewLine}{Exception}";

// Единые константы Class/Method для логов топ-уровня (требование Логирование.md:
// каждое сообщение содержит Class={Class}, Method={Method})
const string ClassName = "WebShelf.Program";
const string MethodName = "Main";

// Лог последнего запуска (только Debug): перед каждым стартом очищается,
// поэтому содержит лог только текущего запуска. Объявлена внутри #if DEBUG:
// в Release-сборке не используется, а вне условной компиляции порождала
// предупреждение CS0219 (отложенное наблюдение №3, закрыто шагом 9).
#if DEBUG
const string LastLogFileName = "Last.log";
#endif

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

// Криптографические сервисы (шаг 8 декомпозиции, улучшение У3): KeyStore и
// CryptoEngine переведены со статического фасада на инстансную модель. Создаются
// вручную до сборки хоста — Data и инициализаторы секций используют их при чтении
// Server.conf, когда DI-контейнер ещё не существует. Готовые экземпляры ниже
// регистрируются в DI как singleton'ы (AddSingleton(instance)).
KeyStore keyStore = new();
CryptoEngine cryptoEngine = new();

// Единственный экземпляр хранилища системных данных. Создаётся до сборки хоста:
// схема, порт и домен из Server.conf нужны при конфигурации хоста (UseUrls, cookie).
// Этот же экземпляр ниже регистрируется в DI как singleton.
Data data = new(keyStore, cryptoEngine);

try
{
    Log.Information("WebShelf запускается. Class={Class}, Method={Method}", ClassName, MethodName);

    string version = ThisAssembly.AssemblyInformationalVersion.Split('+')[0];

    string commitShort = ThisAssembly.GitCommitId is { Length: >= 10 } id ? id[..10] : ThisAssembly.GitCommitId ?? "unknown";

    Log.Information(
        "Версия: {Version}, Commit={Commit}. Class={Class}, Method={Method}",
        version,
        commitShort,
        ClassName, MethodName);

    // Один экземпляр на учётную запись Windows.
    // return (вместо Environment.Exit) гарантирует выполнение finally:
    // освобождение мьютекса и CloseAndFlush — без потери последних сообщений лога.
    if (!InstanceLock.TryAcquire())
    {
        return 1;
    }

    // InstanceId ДО MasterKey и конфигурации
    string? instanceId = keyStore.EnsureInstanceId();
    if (string.IsNullOrWhiteSpace(instanceId))
    {
        Log.Fatal(
            "Не удалось обеспечить InstanceId (реестр/DPAPI). Приложение останавливается. Class={Class}, Method={Method}",
            ClassName, MethodName);
        return 1;
    }

    data.SetInstanceId(instanceId);
    Log.Information(
        "InstanceId готов. Short={Short}. Class={Class}, Method={Method}",
        data.InstanceIdShort, ClassName, MethodName);

    if (!await data.ReadConfigAsync())
    {
        Log.Fatal("Конфигурация не загружена. Приложение останавливается. Class={Class}, Method={Method}", ClassName, MethodName);
        return 1;
    }

    // --- Сервисная инфраструктура БД (каркас, дамп, сброс / обновление структуры) ---
    // Новый шаг порядка старта (ТЗ «Сервисная инфраструктура БД»): после
    // DatabaseSection (создание Database + проверка доступности) и до передачи
    // управления остальному приложению — синхронно с точки зрения старта (await).
    // Приложение не начинает работу на «чужой» схеме: при несовпадении с каркасом
    // и выключенном автосбросе (dbautoschemareset=false) старт прерывается (fail-fast),
    // данные не затрагиваются. Изменения выполняются только после успешного дампа
    // (или на пустой схеме).
    if (data.Database is not Database database)
    {
        Log.Fatal(
            "База данных не инициализирована после загрузки конфигурации. Приложение останавливается. Class={Class}, Method={Method}",
            ClassName, MethodName);
        return 1;
    }

    if (data.DbSchemaOptions is not SchemaBootstrapperOptions dbSchemaOptions)
    {
        Log.Fatal(
            "Параметры сервисной инфраструктуры БД не инициализированы. Приложение останавливается. Class={Class}, Method={Method}",
            ClassName, MethodName);
        return 1;
    }

    if (!await DbBootstrapper.EnsureSchemaAsync(database, dbSchemaOptions))
    {
        Log.Fatal(
            "Не удалось обеспечить соответствие структуры БД каркасу. Приложение останавливается. Class={Class}, Method={Method}",
            ClassName, MethodName);
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
    // После успешного чтения конфигурации домен гарантированно инициализирован;
    // явная проверка вместо null-forgiving ('!') — не доверяем инварианту вслепую
    if (data.Domain is not Domain initializedDomain)
    {
        Log.Fatal(
            "Домен не инициализирован после загрузки конфигурации. Приложение останавливается. Class={Class}, Method={Method}",
            ClassName, MethodName);
        return 1;
    }

    Domain domain = initializedDomain;

    // Управление группами безопасности AD — AdGroupManager (шаг 7 декомпозиции):
    // контекст подключения (имя домена, сервисная учётная запись) и короткий
    // префикс InstanceId передаются явно, класс не зависит от Domain и Data
    AdGroupManager groupManager = new(domain.Name, data.InstanceIdShort, domain.GetDecryptedUser, domain.GetDecryptedPassword);

    if (!RoleCatalog.Validate())
    {
        Log.Fatal(
            "Каталог ролей неконсистентен (дубликаты или пустые значения). Приложение останавливается. Class={Class}, Method={Method}",
            ClassName, MethodName);
        return 1;
    }

    List<string> groupNameTemplates =
    [
        // Группа доступа Users — не роль: шаблон хранится в Domain
        $"WebShelf-{AdNames.InstanceIdShortPlaceholder}-{Domain.UsersGroupSuffix}",
        // Шаблоны ролевых групп — по одной на каждую роль каталога (Гость исключён)
        .. RoleCatalog.BuildGroupNameTemplates()
    ];

    if (!groupManager.FillRequiredGroupsFromTemplates(groupNameTemplates))
    {
        Log.Fatal(
            "Не удалось сформировать список необходимых групп безопасности AD. Приложение останавливается. Class={Class}, Method={Method}",
            ClassName, MethodName);
        return 1;
    }

    if (!groupManager.EnsureRequiredGroupsExist())
    {
        Log.Fatal(
            "Не удалось создать необходимые группы безопасности AD. Приложение останавливается. Class={Class}, Method={Method}",
            ClassName, MethodName);
        return 1;
    }

    // Требование: в системе всегда должен быть минимум один администратор.
    // Проверяется после создания групп: если в группе администраторов нет ни одного
    // участника — предупреждение в лог (запуск не блокируется: группа могла быть
    // только что создана и ждёт первого участника).
    string? adminGroup = RoleCatalog.Administrator.GroupSuffix is string adminGroupSuffix
        ? domain.GetExpandedGroupName(adminGroupSuffix)
        : null;
    if (adminGroup is not null)
    {
        List<string>? adminMembers = domain.GetGroupMemberNames(adminGroup);
        if (adminMembers is not { Count: > 0 })
        {
            Log.Warning(
                "В группе администраторов {Group} нет участников — нарушено требование наличия минимум одного администратора. Class={Class}, Method={Method}",
                adminGroup, ClassName, MethodName);
        }
    }

    // Предупреждение о небезопасной схеме: при http cookie аутентификации
    // передаются без флага Secure и могут быть перехвачены в канале связи.
    if (string.Equals(data.Scheme, "http", StringComparison.OrdinalIgnoreCase))
    {
        Log.Warning(
            "Схема http: cookie аутентификации передаются без защиты Secure. Рекомендуется использовать https. Class={Class}, Method={Method}",
            ClassName, MethodName);
    }

    WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

    // Единая настройка Serilog для bootstrap-логгера и хоста (без дублирования)
    builder.Host.UseSerilog((context, services, configuration) => ApplySerilogDefaults(configuration));

    // Порт гарантирован успешным ReadConfigAsync; явная проверка вместо null-forgiving ('!')
    if (data.Port is not int listenPort)
    {
        Log.Fatal(
            "Порт прослушивания не задан. Приложение останавливается. Class={Class}, Method={Method}",
            ClassName, MethodName);
        return 1;
    }

    // Схема и порт только из Server.conf (независимо от launchSettings.json и профилей http/https)
    string listenUrl = $"{data.Scheme}://0.0.0.0:{listenPort}";
    builder.WebHost.UseUrls(listenUrl);
    Log.Information(
        "Прослушивание {ListenUrl} (Server.conf). Class={Class}, Method={Method}",
        listenUrl, ClassName, MethodName);

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
                ClassName, MethodName);
            return 1;
        }

        // Локальная переменная: переносит non-null состояние в замыкание ConfigureKestrel
        X509Certificate2 tlsCertificate = data.TlsCertificate;

        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Any, listenPort, listenOptions =>
            {
                listenOptions.UseHttps(tlsCertificate);
            });
        });

        Log.Information(
            "TLS-сертификат привязан к Kestrel. Subject={Subject}, NotAfter={NotAfter}. Class={Class}, Method={Method}",
            tlsCertificate.Subject, tlsCertificate.NotAfter, ClassName, MethodName);
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
        keysPath, ClassName, MethodName);
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

    // Криптографические сервисы — готовые singleton-экземпляры, созданные выше
    // до Data: инициализаторы секций использовали их при чтении конфигурации,
    // потребители из DI получают те же экземпляры (шаг 8 декомпозиции, У3)
    builder.Services.AddSingleton(keyStore);
    builder.Services.AddSingleton(cryptoEngine);

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
    if (data.RoleCacheOptions is not RoleCacheOptions roleCacheOptions)
    {
        Log.Fatal(
            "Параметры ролевой модели не инициализированы. Приложение останавливается. Class={Class}, Method={Method}",
            ClassName, MethodName);
        return 1;
    }

    builder.Services.AddSingleton(roleCacheOptions);
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
    Log.Fatal(ex, "Исключение в {Class}.{Method}", ClassName, MethodName);
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
            // formatProvider: инвариантная культура — формат сообщений и временных меток
            // не зависит от локали ОС (CA1305); Serilog по умолчанию использует invariant,
            // здесь это зафиксировано явно
            .WriteTo.Debug(outputTemplate: LogOutputTemplate, formatProvider: CultureInfo.InvariantCulture)
            .WriteTo.File(
                path: Path.Combine(AppContext.BaseDirectory, "logs", "webshelf-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 30,
                shared: true,
                outputTemplate: LogOutputTemplate,
                formatProvider: CultureInfo.InvariantCulture);

#if DEBUG
        // Дублируем лог в Last.log: файл очищается перед каждым Debug-стартом,
        // поэтому содержит только текущий запуск. shared: true обязателен —
        // bootstrap-логгер и логгер хоста пишут в один файл одновременно.
        config = config.WriteTo.File(
            path: Path.Combine(AppContext.BaseDirectory, "logs", LastLogFileName),
            shared: true,
            outputTemplate: LogOutputTemplate,
            formatProvider: CultureInfo.InvariantCulture);
#endif

        return config;
    }
    catch (Exception ex)
    {
        Log.Error(ex, "Исключение в {Class}.{Method}", className, method);
        throw;
    }
}
