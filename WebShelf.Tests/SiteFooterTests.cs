using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.Web.HtmlRendering;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WebShelf.Components.Shared;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты футера сайта (SiteFooter): состав ссылок на политики обработки
/// cookie и персональных данных, отсутствие надписи WebShelf, размещение
/// ссылок по центру с визуальным разделением. Рендер выполняется через
/// HtmlRenderer (статический SSR, как в MainLayoutCookieConsentTests).
/// </summary>
public class SiteFooterTests
{
    /// <summary>
    /// Рендерит футер через HtmlRenderer и возвращает разметку.
    /// Футер — статический компонент без параметров и инжекций.
    /// </summary>
    private static async Task<string> RenderFooterAsync()
    {
        ServiceCollection services = new();
        services.AddLogging();

        await using ServiceProvider provider = services.BuildServiceProvider();
        await using HtmlRenderer renderer = new(provider, provider.GetRequiredService<ILoggerFactory>());

        return await renderer.Dispatcher.InvokeAsync(async () =>
        {
            HtmlRootComponent output = await renderer.RenderComponentAsync<SiteFooter>();
            return output.ToHtmlString();
        });
    }

    /// <summary>
    /// Футер содержит статичные ссылки на обе политики: обработку файлов
    /// cookie (/cookie-policy.html) и обработку персональных данных
    /// (/personal-data-policy.html).
    /// </summary>
    [Fact]
    public async Task Render_Footer_ContainsBothPolicyLinks()
    {
        string html = await RenderFooterAsync();

        Assert.Contains("href=\"/cookie-policy.html\"", html);
        Assert.Contains("Политика обработки файлов cookie", html);
        Assert.Contains("href=\"/personal-data-policy.html\"", html);
        Assert.Contains("Политика обработки персональных данных", html);
    }

    /// <summary>
    /// Надпись WebShelf из футера удалена (задача: убрать надпись WebShelf).
    /// </summary>
    [Fact]
    public async Task Render_Footer_NoWebShelfAppName()
    {
        string html = await RenderFooterAsync();

        Assert.DoesNotContain("ws-footer-appname", html);
        Assert.DoesNotContain("WebShelf", html);
    }

    /// <summary>
    /// Ссылки на политики размещены в центре футера: сгруппированы
    /// в контейнер ws-footer-links и разделены визуальным разделителем
    /// ws-footer-separator, расположенным между ссылками.
    /// </summary>
    [Fact]
    public async Task Render_Footer_LinksCenteredAndSeparated()
    {
        string html = await RenderFooterAsync();

        Assert.Contains("ws-footer-links", html);
        Assert.Contains("ws-footer-separator", html);

        // Разделитель находится между ссылками на политики
        int cookieLinkIndex = html.IndexOf("/cookie-policy.html", StringComparison.Ordinal);
        int separatorIndex = html.IndexOf("ws-footer-separator", StringComparison.Ordinal);
        int personalDataLinkIndex = html.IndexOf("/personal-data-policy.html", StringComparison.Ordinal);

        Assert.True(cookieLinkIndex >= 0, "Ссылка на политику cookie не найдена");
        Assert.True(separatorIndex >= 0, "Разделитель ссылок не найден");
        Assert.True(personalDataLinkIndex >= 0, "Ссылка на политику персональных данных не найдена");
        Assert.True(cookieLinkIndex < separatorIndex, "Разделитель должен идти после ссылки на политику cookie");
        Assert.True(separatorIndex < personalDataLinkIndex, "Разделитель должен идти перед ссылкой на политику персональных данных");
    }

    /// <summary>
    /// Ссылки — обычные статичные переходы (не Blazor-роутинг): у футера нет
    /// интерактивных атрибутов и обработчиков, разметка полностью статична.
    /// </summary>
    [Fact]
    public async Task Render_Footer_StaticMarkupWithoutInterop()
    {
        string html = await RenderFooterAsync();

        Assert.Contains("<footer class=\"ws-footer\">", html);
        Assert.DoesNotContain("<!--blazor", html);
    }
}
