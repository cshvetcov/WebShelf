using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.Web.HtmlRendering;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.JSInterop;
using WebShelf.Classes.Service;
using WebShelf.Components.Layout;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты подключения баннера согласия на обработку cookie в MainLayout
/// (исправление проблемы «баннер не отображается при cookieconsent=true»).
/// Включённому баннеру задаётся интерактивный режим InteractiveServer:
/// чтение решения из localStorage выполняется через JS interop в
/// OnAfterRenderAsync и невозможно в статическом рендере, а layout
/// рендерится статически (интерактивная граница страницы не охватывает
/// layout). Выключенный баннер (по умолчанию) остаётся статическим:
/// без обращений к JS и без участия в circuit. Проверка выполняется через
/// <see cref="HtmlRenderer"/> — тот же статический рендер, которым
/// Blazor Web App отвечает на документ-запросы: среда без интерактивной
/// платформы сообщает о запрошенной интерактивной границе исключением,
/// в котором названы компонент и режим рендера.
/// </summary>
public class MainLayoutCookieConsentTests
{
    /// <summary>
    /// Имитация <see cref="IJSRuntime"/> статического рендера: любой вызов
    /// interop невозможен — в реальном статическом рендере фреймворк
    /// подставляет нерабочую реализацию с тем же поведением.
    /// </summary>
    private sealed class StaticRenderJsRuntime : IJSRuntime
    {
        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args)
            => throw new InvalidOperationException("JS interop недоступен в статическом рендере.");

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args)
            => throw new InvalidOperationException("JS interop недоступен в статическом рендере.");
    }

    /// <summary>
    /// Рендерит MainLayout статически (<see cref="HtmlRenderer"/>) с данными
    /// <paramref name="data"/>. Компонентам предоставляются Data, подмена
    /// источника текстов политик (CookieConsent после подключения журнала
    /// редакций читает номер cookie-редакции через IPolicyContentSource) и
    /// нерабочий IJSRuntime статического рендера.
    /// </summary>
    /// <param name="data">Хранилище системных данных (конфигурация баннера).</param>
    /// <returns>HTML-разметка MainLayout.</returns>
    private static async Task<string> RenderMainLayoutAsync(Data data)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton(data);
        services.AddSingleton<WebShelf.Classes.Service.IPolicyContentSource>(new FakePolicyContentSource());
        services.AddSingleton<IJSRuntime>(new StaticRenderJsRuntime());

        await using ServiceProvider provider = services.BuildServiceProvider();
        await using HtmlRenderer renderer = new(provider, provider.GetRequiredService<ILoggerFactory>());

        return await renderer.Dispatcher.InvokeAsync(async () =>
        {
            HtmlRootComponent output = await renderer.RenderComponentAsync<MainLayout>();
            return output.ToHtmlString();
        });
    }

    /// <summary>
    /// При включённом ключе cookieconsent MainLayout запрашивает для
    /// CookieConsent интерактивную границу InteractiveServer: статический
    /// рендер в среде без интерактивной платформы сообщает об этом
    /// исключением, называя компонент и режим рендера.
    /// </summary>
    [Fact]
    public async Task Render_BannerEnabled_CookieConsentRequestsInteractiveServer()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "domainname=webshelf-test.invalid",
                "scheme=http",
                "port=38080",
                "cookieconsent=true");

            Data data = DataConfigTestHelpers.CreateData(path);
            data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");
            await data.ReadConfigAsync();

            // Домен недоступен — конфигурация в целом не загружена,
            // но скалярная секция cookieconsent инициализирована
            Assert.NotNull(data.CookieConsentOptions);
            Assert.True(data.CookieConsentOptions.BannerEnabled);

            NotSupportedException ex =
                await Assert.ThrowsAsync<NotSupportedException>(() => RenderMainLayoutAsync(data));

            Assert.Contains("WebShelf.Components.Shared.CookieConsent", ex.Message);
            Assert.Contains("InteractiveServerRenderMode", ex.Message);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// При выключенном баннере (конфигурация не инициализирована) MainLayout
    /// рендерится полностью статически: футер и blazor-error-ui присутствуют,
    /// разметка баннера и интерактивные границы отсутствуют — компонент
    /// не обращается к JS и не создаёт цепочек interop.
    /// </summary>
    [Fact]
    public async Task Render_BannerDisabled_NoInteropAndNoBannerMarkup()
    {
        Data data = DataConfigTestHelpers.CreateData();

        string html = await RenderMainLayoutAsync(data);

        Assert.Contains("ws-footer", html);
        Assert.Contains("blazor-error-ui", html);
        Assert.DoesNotContain("ws-cookie-consent", html);
        Assert.DoesNotContain("<!--blazor", html);
    }
}
