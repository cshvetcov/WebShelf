using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты middleware заголовков безопасности: проверяется состав защитных
/// заголовков (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
/// Permissions-Policy) и передача обработки дальше по конвейеру.
/// </summary>
public class SecurityHeadersMiddlewareTests
{
    /// <summary>
    /// Middleware добавляет все защитные заголовки в ответ и вызывает
    /// следующий делегат конвейера.
    /// </summary>
    [Fact]
    public async Task Invoke_AddsAllSecurityHeaders_AndCallsNext()
    {
        IServiceProvider services = new ServiceCollection().BuildServiceProvider();
        IApplicationBuilder appBuilder = new ApplicationBuilder(services);
        appBuilder.UseWebShelfSecurityHeaders();
        RequestDelegate pipeline = appBuilder.Build();

        HttpContext context = new DefaultHttpContext();
        await pipeline(context);

        IHeaderDictionary headers = context.Response.Headers;

        Assert.Equal("DENY", headers["X-Frame-Options"].ToString());
        Assert.Equal("nosniff", headers["X-Content-Type-Options"].ToString());
        Assert.Equal("strict-origin-when-cross-origin", headers["Referrer-Policy"].ToString());
        Assert.Equal("camera=(), microphone=(), geolocation=()", headers["Permissions-Policy"].ToString());
    }

    /// <summary>
    /// Content-Security-Policy содержит ключевые директивы:
    /// same-origin по умолчанию, запрет скриптов со стороны и запрет встраивания в iframe.
    /// </summary>
    [Fact]
    public async Task Invoke_ContentSecurityPolicy_ContainsKeyDirectives()
    {
        IServiceProvider services = new ServiceCollection().BuildServiceProvider();
        IApplicationBuilder appBuilder = new ApplicationBuilder(services);
        appBuilder.UseWebShelfSecurityHeaders();
        RequestDelegate pipeline = appBuilder.Build();

        HttpContext context = new DefaultHttpContext();
        await pipeline(context);

        string csp = context.Response.Headers["Content-Security-Policy"].ToString();

        Assert.Contains("default-src 'self'", csp);
        Assert.Contains("script-src 'self'", csp);
        Assert.Contains("connect-src 'self'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.Contains("object-src 'none'", csp);
        Assert.Contains("base-uri 'self'", csp);
        Assert.Contains("form-action 'self'", csp);
    }

    /// <summary>
    /// Middleware разрешает inline-стили (используются оболочкой окон AppWindow)
    /// и data:-изображения.
    /// </summary>
    [Fact]
    public async Task Invoke_ContentSecurityPolicy_AllowsInlineStylesAndDataImages()
    {
        IServiceProvider services = new ServiceCollection().BuildServiceProvider();
        IApplicationBuilder appBuilder = new ApplicationBuilder(services);
        appBuilder.UseWebShelfSecurityHeaders();
        RequestDelegate pipeline = appBuilder.Build();

        HttpContext context = new DefaultHttpContext();
        await pipeline(context);

        string csp = context.Response.Headers["Content-Security-Policy"].ToString();

        Assert.Contains("style-src 'self' 'unsafe-inline'", csp);
        Assert.Contains("img-src 'self' data:", csp);
    }
}
