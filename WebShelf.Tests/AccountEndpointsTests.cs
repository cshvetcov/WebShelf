using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using System.Globalization;
using System.Net;
using WebShelf.Classes.DC;
using WebShelf.Classes.Security;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты эндпоинтов входа/выхода (<c>AccountEndpoints</c>, шаг 1 декомпозиции):
/// таблица случаев <c>IsLocalUrl</c>, ветки обработчика входа (ручной контур CSRF,
/// блокировка перебора, отсутствие домена, сбой AD) и обработчика выхода
/// (CSRF, различение fetch-запроса и обычного перехода).
/// Antiforgery и сервис аутентификации подменяются фейками
/// (<see cref="AccountEndpointTestFakes"/>), LoginGuard и RoleResolver —
/// реальные экземпляры на тестовых данных.
/// Сценарий успешного входа (состав клеймов, сроки cookie «Запомнить меня»)
/// требует живого AD — ValidateAdCredentials нельзя подменить без изменения
/// производственного кода — и проверяется ручной смоук-проверкой на Windows.
/// </summary>
public class AccountEndpointsTests : IDisposable
{
    /// <summary>Тестируемая защита от перебора: свежий экземпляр на каждый тест.</summary>
    private readonly LoginGuard _guard = new();

    /// <summary>Подмена antiforgery-сервиса: поведение настраивается в каждом тесте.</summary>
    private readonly AccountEndpointTestFakes.FakeAntiforgery _antiforgery = new();

    /// <summary>Подмена сервиса аутентификации: фиксирует вызовы SignIn/SignOut.</summary>
    private readonly AccountEndpointTestFakes.FakeAuthenticationService _authentication = new();

    /// <summary>
    /// Резолвер ролей на подмене источника групп: до ветки успешного входа
    /// обработчиком не вызывается, создаётся реальным конструктором.
    /// </summary>
    private readonly RoleResolver _roleResolver;

    /// <summary>
    /// Создаёт резолвер ролей на фейковом источнике групп и фиксированном времени.
    /// </summary>
    public AccountEndpointsTests()
    {
        RoleTestFakes.FakeAdGroupSource adSource = new();
        RoleCacheOptions options = RoleCacheOptions.FromTimeSpans(
            TimeSpan.FromSeconds(30),
            TimeSpan.FromSeconds(10));

        _roleResolver = new RoleResolver(adSource, options, new RoleTestFakes.FakeTimeProvider());
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _guard.Dispose();
    }

    /// <summary>
    /// Создаёт контекст POST-запроса с заданным IP клиента; в RequestServices
    /// доступна подмена сервиса аутентификации.
    /// </summary>
    private DefaultHttpContext CreateContext(string clientIp = "10.0.0.1")
    {
        DefaultHttpContext context = new();
        context.Request.Method = "POST";
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Connection.RemoteIpAddress = IPAddress.Parse(clientIp);

        IServiceCollection services = new ServiceCollection();

        // Выполнение IResult (редиректы) в .NET 10 пишет диагностику через
        // ILoggerFactory — регистрируем минимальный набор сервисов логирования
        services.AddLogging();
        services.AddSingleton<IAuthenticationService>(_authentication);
        context.RequestServices = services.BuildServiceProvider();

        return context;
    }

    /// <summary>
    /// Создаёт контекст POST-запроса с заполненной формой входа.
    /// <see langword="null"/> в параметрах означает отсутствие ключа в форме
    /// (для проверки веток «пустое имя» и «пароль не передан»).
    /// </summary>
    private DefaultHttpContext CreateLoginContext(
        string? username = "ivanov",
        string? password = "UserPassword123!",
        string clientIp = "10.0.0.1")
    {
        DefaultHttpContext context = CreateContext(clientIp);

        Dictionary<string, StringValues> form = new();
        if (username is not null)
        {
            form["username"] = username;
        }

        if (password is not null)
        {
            form["password"] = password;
        }

        context.Request.Form = new FormCollection(form);

        return context;
    }

    /// <summary>
    /// Выполняет результат обработчика и возвращает код статуса ответа и адрес
    /// редиректа (заголовок Location; пустая строка, если редиректа нет).
    /// </summary>
    private static async Task<(int StatusCode, string Location)> ExecuteAsync(IResult result, HttpContext context)
    {
        await result.ExecuteAsync(context);

        return (context.Response.StatusCode, context.Response.Headers.Location.ToString());
    }

    #region IsLocalUrl

    /// <summary>
    /// Таблица случаев <c>IsLocalUrl</c>: локальными считаются только абсолютные
    /// пути внутри приложения ('/' и '/путь'); протокол-относительные адреса
    /// ('//host' и '/\host'), абсолютные URL и строки без ведущего слеша
    /// отклоняются — защита от open redirect при обработке ReturnUrl.
    /// </summary>
    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("/", true)]
    [InlineData("//", false)]
    [InlineData("//evil.example.com", false)]
    [InlineData("/\\evil.example.com", false)]
    [InlineData("\\\\evil.example.com", false)]
    [InlineData("http://evil.example.com", false)]
    [InlineData("https://internal/page", false)]
    [InlineData("/home/documents", true)]
    [InlineData("/home?filter=1#top", true)]
    [InlineData("relative/path", false)]
    [InlineData(" /leading-space", false)]
    [InlineData("/путь/с-кириллицей", true)]
    public void IsLocalUrl_Table(string? url, bool expected)
    {
        bool actual = AccountEndpoints.IsLocalUrl(url);

        Assert.Equal(expected, actual);
    }

    #endregion

    #region LoginAsync

    /// <summary>
    /// Неверный antiforgery-токен: ручная проверка (второй контур CSRF)
    /// возвращает дружелюбный редирект на форму входа с error=invalid.
    /// </summary>
    [Fact]
    public async Task LoginAsync_InvalidAntiforgeryToken_RedirectsToEntryInvalid()
    {
        _antiforgery.ThrowValidationException = true;
        DefaultHttpContext context = CreateLoginContext();
        Data data = new();

        IResult result = await AccountEndpoints.LoginAsync(context, _antiforgery, _guard, _roleResolver, data);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(302, statusCode);
        Assert.Equal("/entry?error=invalid", location);
    }

    /// <summary>
    /// Вход во время активной блокировки: редирект с error=locked и остатком
    /// секунд блокировки. Неудачные попытки фиксировались по IP и имени
    /// пользователя; конфигурация не прочитана — домен отсутствует.
    /// </summary>
    [Fact]
    public async Task LoginAsync_LockedOut_RedirectsToEntryLocked()
    {
        int lockoutSeconds = 0;
        for (int i = 0; i < LoginGuard.MaxFailedAttempts; i++)
        {
            lockoutSeconds = _guard.RecordFailure("10.0.0.1", "ivanov@example.local");
        }

        Assert.True(lockoutSeconds > 0, "Предусловие: блокировка должна быть активна.");

        DefaultHttpContext context = CreateLoginContext();
        Data data = new();

        IResult result = await AccountEndpoints.LoginAsync(context, _antiforgery, _guard, _roleResolver, data);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(302, statusCode);
        Assert.StartsWith("/entry?error=locked&retry=", location);

        int retrySeconds = int.Parse(location[(location.LastIndexOf('=') + 1)..], CultureInfo.InvariantCulture);
        Assert.InRange(retrySeconds, 1, lockoutSeconds);
    }

    /// <summary>
    /// Домен не инициализирован (конфигурация не прочитана): канонизация имени
    /// невозможна, попытка фиксируется только по IP-ключу и завершается
    /// редиректом error=invalid.
    /// </summary>
    [Fact]
    public async Task LoginAsync_DomainMissing_RedirectsToEntryInvalid()
    {
        DefaultHttpContext context = CreateLoginContext(username: "ivanov", password: "UserPassword123!");
        Data data = new();

        IResult result = await AccountEndpoints.LoginAsync(context, _antiforgery, _guard, _roleResolver, data);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(302, statusCode);
        Assert.Equal("/entry?error=invalid", location);
    }

    /// <summary>
    /// Пустое имя пользователя: отказ без обращения к AD, редирект error=invalid.
    /// </summary>
    [Fact]
    public async Task LoginAsync_EmptyUsername_RedirectsToEntryInvalid()
    {
        DefaultHttpContext context = CreateLoginContext(username: "", password: "UserPassword123!");
        Data data = new();

        IResult result = await AccountEndpoints.LoginAsync(context, _antiforgery, _guard, _roleResolver, data);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(302, statusCode);
        Assert.Equal("/entry?error=invalid", location);
    }

    /// <summary>
    /// Пароль отсутствует в форме (ключ не передан): отказ, редирект error=invalid.
    /// </summary>
    [Fact]
    public async Task LoginAsync_MissingPassword_RedirectsToEntryInvalid()
    {
        DefaultHttpContext context = CreateLoginContext(username: "ivanov", password: null);
        Data data = new();

        IResult result = await AccountEndpoints.LoginAsync(context, _antiforgery, _guard, _roleResolver, data);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(302, statusCode);
        Assert.Equal("/entry?error=invalid", location);
    }

    /// <summary>
    /// Пятая неудачная попытка (порог MaxFailedAttempts) происходит внутри
    /// обработчика: блокировка включается, редирект содержит точный остаток
    /// первой блокировки — 30 секунд.
    /// </summary>
    [Fact]
    public async Task LoginAsync_FailureReachesThreshold_RedirectsToEntryLocked()
    {
        // Четыре попытки заранее — пятая выполняется внутри обработчика
        for (int i = 0; i < LoginGuard.MaxFailedAttempts - 1; i++)
        {
            _guard.RecordFailure("10.0.0.1", null);
        }

        DefaultHttpContext context = CreateLoginContext();
        Data data = new();

        IResult result = await AccountEndpoints.LoginAsync(context, _antiforgery, _guard, _roleResolver, data);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(302, statusCode);
        Assert.Equal("/entry?error=locked&retry=30", location);
    }

    /// <summary>
    /// Неожиданное исключение внутри обработчика (не AntiforgeryValidationException):
    /// отказоустойчивый редирект error=server без раскрытия причины клиенту.
    /// </summary>
    [Fact]
    public async Task LoginAsync_UnexpectedException_RedirectsToEntryServer()
    {
        _antiforgery.ThrowUnexpectedException = true;
        DefaultHttpContext context = CreateLoginContext();
        Data data = new();

        IResult result = await AccountEndpoints.LoginAsync(context, _antiforgery, _guard, _roleResolver, data);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(302, statusCode);
        Assert.Equal("/entry?error=server", location);
    }

    /// <summary>
    /// Недоступный AD при инициализированном домене: ValidateAdCredentials
    /// завершается исключением, обработчик возвращает error=server.
    /// Домен создаётся через тестовую точку Data.CreateWithDomain с именем
    /// в зоне .invalid (RFC 6761 — гарантированно не существует, контроллер
    /// домена недоступен без таймаутов). Выполняется только на Windows:
    /// конструктор Domain требует мастер-ключ (HKCU + DPAPI).
    /// </summary>
    [Fact]
    public async Task LoginAsync_AdUnavailable_RedirectsToEntryServer()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!; // SkipUnless гарантирует ненулевое значение при продолжении

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("ws.invalid", "000000000000", encryptedUser, encryptedPassword);
        Data data = Data.CreateWithDomain(domain);

        DefaultHttpContext context = CreateLoginContext(username: "ivanov", password: "WrongPassword123!");

        IResult result = await AccountEndpoints.LoginAsync(context, _antiforgery, _guard, _roleResolver, data);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(302, statusCode);
        Assert.Equal("/entry?error=server", location);
    }

    #endregion

    #region LogoutAsync

    /// <summary>
    /// Неверный antiforgery-токен при выходе: голый 400 (в отличие от входа,
    /// где редирект на форму) — семантика двух контуров различается намеренно.
    /// </summary>
    [Fact]
    public async Task LogoutAsync_InvalidAntiforgeryToken_ReturnsBadRequest()
    {
        _antiforgery.ThrowValidationException = true;
        DefaultHttpContext context = CreateContext();

        IResult result = await AccountEndpoints.LogoutAsync(context, _antiforgery);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(400, statusCode);
        Assert.Empty(_authentication.SignOutCalls);
    }

    /// <summary>
    /// Fetch-запрос (Accept: application/json): выход выполняется по схеме
    /// cookie-аутентификации, ответ 204 без редиректа — клиент с
    /// redirect:manual сам переходит на /entry.
    /// </summary>
    [Fact]
    public async Task LogoutAsync_FetchByAcceptHeader_ReturnsNoContent()
    {
        DefaultHttpContext context = CreateContext();
        context.Request.Headers.Accept = "application/json";

        IResult result = await AccountEndpoints.LogoutAsync(context, _antiforgery);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(204, statusCode);
        Assert.Single(_authentication.SignOutCalls);
        Assert.Equal(CookieAuthenticationDefaults.AuthenticationScheme, _authentication.SignOutCalls[0].Scheme);
    }

    /// <summary>
    /// Fetch-запрос (заголовок X-Requested-With: XMLHttpRequest): ответ 204.
    /// </summary>
    [Fact]
    public async Task LogoutAsync_FetchByXhrHeader_ReturnsNoContent()
    {
        DefaultHttpContext context = CreateContext();
        context.Request.Headers["X-Requested-With"] = "XMLHttpRequest";

        IResult result = await AccountEndpoints.LogoutAsync(context, _antiforgery);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(204, statusCode);
        Assert.Single(_authentication.SignOutCalls);
    }

    /// <summary>
    /// Fetch-запрос (заголовок Sec-Fetch-Mode: cors): ответ 204.
    /// </summary>
    [Fact]
    public async Task LogoutAsync_FetchBySecFetchMode_ReturnsNoContent()
    {
        DefaultHttpContext context = CreateContext();
        context.Request.Headers["Sec-Fetch-Mode"] = "cors";

        IResult result = await AccountEndpoints.LogoutAsync(context, _antiforgery);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(204, statusCode);
        Assert.Single(_authentication.SignOutCalls);
    }

    /// <summary>
    /// Обычный POST-переход браузера (Accept: text/html): выход выполняется,
    /// ответ — 302 на /entry.
    /// </summary>
    [Fact]
    public async Task LogoutAsync_BrowserPost_RedirectsToEntry()
    {
        DefaultHttpContext context = CreateContext();
        context.Request.Headers.Accept = "text/html,application/xhtml+xml";

        IResult result = await AccountEndpoints.LogoutAsync(context, _antiforgery);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(302, statusCode);
        Assert.Equal("/entry", location);
        Assert.Single(_authentication.SignOutCalls);
        Assert.Equal(CookieAuthenticationDefaults.AuthenticationScheme, _authentication.SignOutCalls[0].Scheme);
    }

    /// <summary>
    /// Неожиданное исключение при выходе: редирект на /entry без раскрытия
    /// причины; SignOut не выполнялся.
    /// </summary>
    [Fact]
    public async Task LogoutAsync_UnexpectedException_RedirectsToEntry()
    {
        _antiforgery.ThrowUnexpectedException = true;
        DefaultHttpContext context = CreateContext();

        IResult result = await AccountEndpoints.LogoutAsync(context, _antiforgery);
        (int statusCode, string location) = await ExecuteAsync(result, context);

        Assert.Equal(302, statusCode);
        Assert.Equal("/entry", location);
        Assert.Empty(_authentication.SignOutCalls);
    }

    #endregion
}
