using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Serilog;

namespace WebShelf.Classes.Service;

/// <summary>
/// Middleware заголовков безопасности WebShelf.
/// Добавляет в каждый HTTP-ответ защитные заголовки:
/// Content-Security-Policy, X-Content-Type-Options, X-Frame-Options,
/// Referrer-Policy и Permissions-Policy.
/// </summary>
internal static class SecurityHeadersMiddleware
{
    private const string ClassName = "WebShelf.Classes.Service.SecurityHeadersMiddleware";

    /// <summary>
    /// Политика Content Security Policy: скрипты и соединения только same-origin
    /// (включая WebSocket-канал Blazor Server); inline-стили разрешены —
    /// атрибут style используется оболочкой окон AppWindow.
    /// </summary>
    private const string ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "base-uri 'self'; " +
        "form-action 'self'; " +
        "frame-ancestors 'none'; " +
        "object-src 'none'";

    /// <summary>
    /// Регистрирует middleware заголовков безопасности в конвейер обработки.
    /// </summary>
    /// <param name="builder">Строитель приложения.</param>
    /// <returns>Строитель приложения после регистрации middleware.</returns>
    internal static IApplicationBuilder UseWebShelfSecurityHeaders(this IApplicationBuilder builder)
    {
        const string method = nameof(UseWebShelfSecurityHeaders);

        Log.Information(
            "Middleware заголовков безопасности зарегистрирован. Class={Class}, Method={Method}",
            ClassName, method);

        return builder.Use(InvokeAsync);
    }

    /// <summary>
    /// Добавляет защитные заголовки в ответ и передаёт обработку дальше по конвейеру.
    /// </summary>
    /// <param name="context">Текущий HTTP-контекст.</param>
    /// <param name="next">Следующий делегат конвейера.</param>
    private static async Task InvokeAsync(HttpContext context, Func<Task> next)
    {
        const string method = nameof(InvokeAsync);

        try
        {
            IHeaderDictionary headers = context.Response.Headers;

            // Защита от встраивания страницы в iframe (кликджекинг)
            headers["X-Frame-Options"] = "DENY";

            // Запрет интерпретации содержимого иного типа (MIME-sniffing)
            headers["X-Content-Type-Options"] = "nosniff";

            // Не раскрываем полный источник перехода сторонним сайтам
            headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

            // Доступ к камере, микрофону и геолокации приложению не требуется
            headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";

            // Основная политика безопасности контента
            headers["Content-Security-Policy"] = ContentSecurityPolicy;

            await next();
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            throw;
        }
    }
}
