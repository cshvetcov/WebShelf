using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace WebShelf.Classes.Security;

/// <summary>
/// Провайдер состояния аутентификации WebShelf (scoped, по одному на цепочку).
/// Личность берётся из cookie — каркас сеет её через
/// <see cref="IHostEnvironmentAuthenticationStateProvider.SetAuthenticationState"/>
/// при SSR-рендере и старте цепочки. Роль каждый раз вычисляется заново по группам AD
/// и накладывается на клеймы: cookie хранит только личность, привилегии — всегда свежие.
/// При смене роли (push из <see cref="RoleRefreshService"/> через
/// <see cref="RoleChangeNotifier"/>) состояние обновляется уведомлением Blazor —
/// AuthorizeView и лента перерисовываются без перезагрузки страницы.
/// Подписка на события ведётся по имени учётной записи своей цепочки
/// и снимается при её закрытии (<see cref="Dispose"/>).
/// </summary>
internal sealed class AppAuthenticationStateProvider :
    AuthenticationStateProvider,
    IHostEnvironmentAuthenticationStateProvider,
    IDisposable
{
    private const string ClassName = "WebShelf.Classes.Security.AppAuthenticationStateProvider";

    private readonly RoleResolver _resolver;
    private readonly RoleChangeNotifier _notifier;
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>Личность из cookie, посеянная каркасом (SSR-запрос или старт цепочки).</summary>
    private Task<AuthenticationState>? _seeded;

    /// <summary>Актуальное состояние: личность + свежая роль. Обновляется push-ом.</summary>
    private Task<AuthenticationState>? _current;

    /// <summary>Подписка на события смены роли пользователя цепочки; null до построения состояния.</summary>
    private IDisposable? _subscription;

    /// <summary>
    /// Конструктор объявлен <see langword="public"/> (сам класс остаётся internal):
    /// контейнер DI находит только public-конструкторы.
    /// </summary>
    public AppAuthenticationStateProvider(
        RoleResolver roleResolver,
        RoleChangeNotifier changeNotifier,
        IHttpContextAccessor httpContextAccessor)
    {
        _resolver = roleResolver;
        _notifier = changeNotifier;
        _httpContextAccessor = httpContextAccessor;
    }

    /// <summary>
    /// Каркас (SSR-рендер / старт цепочки) передаёт состояние аутентификации из cookie.
    /// Личность сохраняется; роль будет пересчитана при первом обращении
    /// <see cref="GetAuthenticationStateAsync"/>.
    /// </summary>
    public void SetAuthenticationState(Task<AuthenticationState> authenticationStateTask)
    {
        _seeded = authenticationStateTask;
        _current = null;
    }

    /// <summary>
    /// Возвращает актуальное состояние. Первый вызов строит его из посеянной личности
    /// (cookie) со свежей ролью из AD; дальнейшие вызовы возвращают закэшированную
    /// задачу, обновляемую push-ом. Любой сбой построения переводит состояние
    /// в анонимное (fail-secure), а не в faulted-задачу.
    /// </summary>
    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        const string method = nameof(GetAuthenticationStateAsync);

        try
        {
            Task<AuthenticationState>? current = _current;
            if (current is not null)
            {
                return current;
            }

            _current = BuildAsync();
            return _current;
        }
        catch (Exception ex)
        {
            // Синхронный сбой построения (не должен случаться: BuildAsync
            // асинхронная и ловит внутри) — возвращаем анонимное состояние
            Log.Error(ex, "Исключение при получении состояния аутентификации. Class={Class}, Method={Method}", ClassName, method);

            Task<AuthenticationState> anonymous = Task.FromResult(CreateAnonymousState());
            _current = anonymous;
            return anonymous;
        }
    }

    /// <summary>
    /// Строит состояние: личность из cookie + свежая роль из AD, затем подписывается
    /// на события смены роли этого пользователя. Пользователь без группы Users
    /// переводится в анонимное состояние — доступ к системе запрещён целиком (fail-secure).
    /// </summary>
    private async Task<AuthenticationState> BuildAsync()
    {
        const string method = nameof(BuildAsync);

        try
        {
            Task<AuthenticationState>? seedTask = _seeded;
            if (seedTask is null)
            {
                // Посев не пришёл (обращение вне цепочки) — страховка: HttpContext текущего
                // запроса. В .NET 10 IHttpContextAccessor доступен и в цепочках (см. Entry.razor)
                HttpContext? http = _httpContextAccessor.HttpContext;
                if (http?.User.Identity?.IsAuthenticated == true)
                {
                    seedTask = Task.FromResult(new AuthenticationState(http.User));
                }
            }

            if (seedTask is null)
            {
                return CreateAnonymousState();
            }

            AuthenticationState seed = await seedTask.ConfigureAwait(false);
            ClaimsPrincipal seedUser = seed.User;

            if (seedUser.Identity?.IsAuthenticated != true)
            {
                // Анонимный запрос — как есть (форма входа и статические страницы)
                return seed;
            }

            string? username = seedUser.Identity.Name ?? seedUser.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrWhiteSpace(username))
            {
                // Личность без имени — нечего резолвить, отдаём как есть
                return seed;
            }

            // Подписка на события смены роли этого пользователя: опрос идёт
            // от имени singleton-службы, провайдер цепочки — единственный её подписчик.
            // Подписка ставится один раз и снимается при закрытии цепочки (Dispose)
            if (_subscription is null)
            {
                _subscription = _notifier.Subscribe(username, OnRoleChanged);
            }

            RoleResolution? resolution = _resolver.Resolve(username);
            if (resolution is null)
            {
                // AD недоступен и кэша нет: остаёмся на клеймах cookie (роль на момент входа)
                Log.Warning(
                    "Роль не вычислена (AD недоступен, кэш пуст): состояние взято из cookie. Class={Class}, Method={Method}",
                    ClassName, method);
                return seed;
            }

            if (!resolution.HasUsersGroup)
            {
                // Исключён из группы Users — доступ к системе запрещён целиком
                Log.Warning(
                    "Пользователь исключён из группы Users: цепочка переведена в анонимное состояние. Username={User}. Class={Class}, Method={Method}",
                    "UserAccount", ClassName, method);
                return CreateAnonymousState();
            }

            return new AuthenticationState(RebuildPrincipal(seedUser, resolution));
        }
        catch (Exception ex)
        {
            // Асинхронный сбой построения: анонимное состояние вместо faulted-задачи,
            // иначе faulted-задача осталась бы в _current и роняла бы все последующие вызовы
            Log.Error(ex, "Исключение при построении состояния аутентификации. Class={Class}, Method={Method}", ClassName, method);
            return CreateAnonymousState();
        }
    }

    /// <summary>
    /// Обработка push-события из фонового опроса. Вызывается в потоке службы,
    /// поэтому состояние подменяется атомарно, без ожидания. Потеря группы Users —
    /// принудительный выход: цепочка переводится в анонимное состояние.
    /// </summary>
    /// <param name="resolution">Новое состояние ролей пользователя цепочки.</param>
    private void OnRoleChanged(RoleResolution resolution)
    {
        const string method = nameof(OnRoleChanged);

        try
        {
            if (!resolution.HasUsersGroup)
            {
                // Принудительный выход: потеряна группа Users. Cookie остаётся
                // валидным до своего срока, но интерактивные страницы считают
                // пользователя вышедшим (провайдер возвращает анонимное состояние)
                _current = Task.FromResult(CreateAnonymousState());
                NotifyAuthenticationStateChanged(_current!);

                Log.Warning(
                    "Принудительный выход из цепочки: пользователь исключён из группы Users. Username={User}. Class={Class}, Method={Method}",
                    "UserAccount", ClassName, method);
                return;
            }

            Task<AuthenticationState>? current = _current;
            if (current is null || !current.IsCompleted)
            {
                // Состояние ещё не построено: первый Get возьмёт свежую роль сам
                return;
            }

            AuthenticationState state = current.GetAwaiter().GetResult();

            // Смена роли: пересобираем клеймы и уведомляем Blazor —
            // AuthorizeView и лента перерисовываются без перезагрузки страницы
            _current = Task.FromResult(new AuthenticationState(RebuildPrincipal(state.User, resolution)));
            NotifyAuthenticationStateChanged(_current!);

            Log.Information(
                "Роль обновлена в цепочке. OldRole={Old}, NewRole={New}. Username={User}. Class={Class}, Method={Method}",
                state.User.FindFirst(ClaimTypes.Role)?.Value ?? "—",
                resolution.EffectiveRole.SystemName,
                "UserAccount", ClassName, method);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение при обработке события смены роли. Class={Class}, Method={Method}", ClassName, method);
        }
    }

    /// <summary>
    /// Пересобирает принципала: клеймы копируются, кроме транспортных клеймов роли —
    /// их значения обновляются свежими данными из AD.
    /// </summary>
    private static ClaimsPrincipal RebuildPrincipal(ClaimsPrincipal seedUser, RoleResolution resolution)
    {
        List<Claim> claims = seedUser.Claims
            .Where(claim => claim.Type != ClaimTypes.Role && claim.Type != ClaimsPrincipalExtensions.MatchedRolesClaimType)
            .ToList();

        claims.Add(new Claim(ClaimTypes.Role, resolution.EffectiveRole.SystemName));

        if (resolution.MatchedRoles.Count > 0)
        {
            claims.Add(new Claim(
                ClaimsPrincipalExtensions.MatchedRolesClaimType,
                string.Join(",", resolution.MatchedRoles.Select(role => role.SystemName))));
        }

        // AuthenticationType сохраняется: IsAuthenticated остаётся true
        ClaimsIdentity identity = new(claims, seedUser.Identity?.AuthenticationType);
        return new ClaimsPrincipal(identity);
    }

    private static AuthenticationState CreateAnonymousState()
    {
        return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
    }

    /// <summary>
    /// Снимает подписку на события смены роли: цепочка закрыта —
    /// провайдер больше не нужен.
    /// </summary>
    public void Dispose()
    {
        _subscription?.Dispose();
        _subscription = null;
    }
}
