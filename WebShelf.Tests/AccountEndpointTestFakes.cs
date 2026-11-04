using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace WebShelf.Tests;

/// <summary>
/// Подмены для тестов эндпоинтов входа/выхода (AccountEndpointsTests):
/// antiforgery-сервис и сервис аутентификации. Реальные реализации требуют
/// инфраструктуры ASP.NET Core (Data Protection, шифрование cookie),
/// которая не нужна для проверки логики обработчиков.
/// </summary>
public static class AccountEndpointTestFakes
{
    /// <summary>
    /// Подмена <see cref="IAntiforgery"/>: по умолчанию запрос считается валидным
    /// (ValidateRequestAsync завершается успешно). Флаги настраивают выброс
    /// <see cref="AntiforgeryValidationException"/> (невалидный токен) или
    /// произвольного исключения (сбой сервиса) — для проверки веток обработчиков.
    /// Не используемые обработчиками методы выбрасывают
    /// <see cref="NotSupportedException"/>: неожиданный вызов сразу проявится
    /// падением теста.
    /// </summary>
    public sealed class FakeAntiforgery : IAntiforgery
    {
        /// <summary>
        /// Когда <see langword="true"/> — ValidateRequestAsync выбрасывает
        /// <see cref="AntiforgeryValidationException"/> (невалидный токен).
        /// </summary>
        public bool ThrowValidationException { get; set; }

        /// <summary>
        /// Когда <see langword="true"/> — ValidateRequestAsync выбрасывает
        /// <see cref="InvalidOperationException"/> (сбой сервиса, не связанный с токеном).
        /// </summary>
        public bool ThrowUnexpectedException { get; set; }

        /// <inheritdoc />
        public AntiforgeryTokenSet GetAndStoreTokens(HttpContext httpContext) =>
            throw new NotSupportedException("Метод не используется обработчиками входа/выхода.");

        /// <inheritdoc />
        public AntiforgeryTokenSet GetTokens(HttpContext httpContext) =>
            throw new NotSupportedException("Метод не используется обработчиками входа/выхода.");

        /// <inheritdoc />
        public Task<bool> IsRequestValidAsync(HttpContext httpContext) =>
            throw new NotSupportedException("Метод не используется обработчиками входа/выхода.");

        /// <inheritdoc />
        public Task ValidateRequestAsync(HttpContext httpContext)
        {
            if (ThrowUnexpectedException)
            {
                throw new InvalidOperationException("Подмена: сбой antiforgery-сервиса.");
            }

            if (ThrowValidationException)
            {
                throw new AntiforgeryValidationException("Подмена: неверный antiforgery-токен.");
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public void SetCookieTokenAndHeader(HttpContext httpContext) =>
            throw new NotSupportedException("Метод не используется обработчиками входа/выхода.");
    }

    /// <summary>
    /// Подмена <see cref="IAuthenticationService"/>: фиксирует вызовы SignInAsync
    /// и SignOutAsync (схема, принципал, свойства) — для проверки схемы cookie,
    /// состава клеймов и сроков билета. Остальные методы выбрасывают
    /// <see cref="NotSupportedException"/>: обработчики входа/выхода их не вызывают.
    /// </summary>
    public sealed class FakeAuthenticationService : IAuthenticationService
    {
        /// <summary>Зафиксированные вызовы SignInAsync: схема, принципал и свойства билета.</summary>
        public List<(string? Scheme, ClaimsPrincipal Principal, AuthenticationProperties? Properties)> SignInCalls { get; } = [];

        /// <summary>Зафиксированные вызовы SignOutAsync: схема и свойства.</summary>
        public List<(string? Scheme, AuthenticationProperties? Properties)> SignOutCalls { get; } = [];

        /// <inheritdoc />
        public Task SignInAsync(
            HttpContext context,
            string? scheme,
            ClaimsPrincipal principal,
            AuthenticationProperties? properties)
        {
            SignInCalls.Add((scheme, principal, properties));
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            SignOutCalls.Add((scheme, properties));
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            throw new NotSupportedException("Метод не используется обработчиками входа/выхода.");

        /// <inheritdoc />
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            throw new NotSupportedException("Метод не используется обработчиками входа/выхода.");

        /// <inheritdoc />
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            throw new NotSupportedException("Метод не используется обработчиками входа/выхода.");
    }
}
