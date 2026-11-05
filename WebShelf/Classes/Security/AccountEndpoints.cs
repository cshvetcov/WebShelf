using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using WebShelf.Classes.DC;
using WebShelf.Classes.Service;

namespace WebShelf.Classes.Security;

/// <summary>
/// Эндпоинты входа и выхода: подключение маршрутов <c>POST /account/login</c>
/// и <c>POST /account/logout</c> и их обработчики. Вынесены из Program.cs
/// (шаг 1 декомпозиции) механически, без изменения поведения: маршруты,
/// состав и сроки cookie-клеймов, схемы ответов и семантика CSRF-проверки
/// сохранены. Обработчики остаются статическими: параметры внедряются
/// minimal-API из DI при каждом запросе, сигнатуры не менялись.
/// </summary>
internal static class AccountEndpoints
{
    /// <summary>
    /// Подключает эндпоинты аккаунта: вход (POST /account/login) и выход
    /// (POST /account/logout). Вызывается из Program.cs вместо прямых
    /// вызовов <c>MapPost</c>.
    /// </summary>
    /// <param name="app">Построитель маршрутов приложения.</param>
    /// <returns>Переданный построитель — для цепочки вызовов.</returns>
    internal static IEndpointRouteBuilder MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapPost("/account/login", LoginAsync);

        // Выход только по POST с antiforgery-током — защита от logout-CSRF
        app.MapPost("/account/logout", LogoutAsync);

        return app;
    }

    /// <summary>
    /// Обработчик POST /account/login — CSRF-проверка, защита от перебора, проверка AD и выдача cookie.
    /// После валидации учётных данных вычисляется роль: свежая LDAP-проверка в обход
    /// кэша (вариант 3) — клейм роли в cookie является только транспортом на момент входа.
    /// </summary>
    /// <param name="context">Контекст текущего HTTP-запроса.</param>
    /// <param name="antiforgery">Сервис проверки antiforgery-токенов.</param>
    /// <param name="loginGuard">Защита от перебора паролей.</param>
    /// <param name="roleResolver">Вычислитель роли пользователя по группам AD.</param>
    /// <param name="data">Хранилище системных данных (инициализированный домен).</param>
    /// <param name="timeProvider">Источник текущего времени (UTC) для срока жизни
    /// cookie: 14 календарных дней при «Запомнить меня», иначе 8 часов.
    /// Не задан (прямой вызов в тестах) — <see cref="TimeProvider.System"/>;
    /// при обработке HTTP-запроса внедряется из DI.</param>
    /// <returns>Результат: редирект на форму входа, исходную страницу либо страницу с ошибкой.</returns>
    internal static async Task<IResult> LoginAsync(
        HttpContext context,
        IAntiforgery antiforgery,
        LoginGuard loginGuard,
        RoleResolver roleResolver,
        Data data,
        TimeProvider? timeProvider = null)
    {
        const string className = "WebShelf.Classes.Security.AccountEndpoints";
        const string method = nameof(LoginAsync);

        TimeProvider clock = timeProvider ?? TimeProvider.System;

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
                : AdNames.NormalizeUserName(username, data.Domain.Name);

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

            // Роль — свежая LDAP-проверка в обход кэша (вариант 3). Отказ (AD недоступен,
            // кэш пуст) или потеря группы Users — вход не выполняется (fail-secure):
            // пароль уже проверен, повторная блокировка не нужна, отдаём server
            RoleResolution? roleState = roleResolver.ResolveFresh(samAccountName);
            if (roleState is null || !roleState.HasUsersGroup)
            {
                Log.Warning(
                    "Вход отклонён: роль недоступна (AD) или нет группы Users. Ip={Ip}. Class={Class}, Method={Method}",
                    clientIp, className, method);
                return Results.Redirect("/entry?error=server");
            }

            List<Claim> claims =
            [
                new(ClaimTypes.Name, samAccountName),
                new(ClaimTypes.NameIdentifier, samAccountName),
                // Эффективная роль — транспорт в cookie на момент входа;
                // источник истины всегда AD (резолвер обновляет роль в цепочке)
                new(ClaimTypes.Role, roleState.EffectiveRole.SystemName)
            ];

            if (roleState.MatchedRoles.Count > 0)
            {
                // Диагностический клейм: все совпавшие роли через запятую
                claims.Add(new Claim(
                    ClaimsPrincipalExtensions.MatchedRolesClaimType,
                    string.Join(",", roleState.MatchedRoles.Select(role => role.SystemName))));
            }

            ClaimsIdentity identity = new(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            ClaimsPrincipal principal = new(identity);

            AuthenticationProperties props = new()
            {
                IsPersistent = rememberMe,
                ExpiresUtc = rememberMe
                    ? clock.GetUtcNow().AddDays(14)
                    : clock.GetUtcNow().AddHours(8)
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
    internal static bool IsLocalUrl(string? url)
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
    /// <param name="context">Контекст текущего HTTP-запроса.</param>
    /// <param name="antiforgery">Сервис проверки antiforgery-токенов.</param>
    /// <returns>
    /// 204 для fetch-запроса (клиент сам переходит на /entry),
    /// иначе редирект на форму входа; 400 — неверный antiforgery-токен.
    /// </returns>
    internal static async Task<IResult> LogoutAsync(
        HttpContext context,
        IAntiforgery antiforgery)
    {
        const string className = "WebShelf.Classes.Security.AccountEndpoints";
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
}
