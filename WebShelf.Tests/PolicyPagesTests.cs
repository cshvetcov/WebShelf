using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Text.Unicode;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.Web.HtmlRendering;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WebShelf.Classes.Service;
using WebShelf.Components.Pages;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты рендера страниц политик (CookiePolicy, PersonalDataPolicy,
/// PolicyArchive) через HtmlRenderer (статический SSR — тот же рендер, которым
/// Blazor отвечает на документ-запросы): оболочка шаблона PolicyDocument,
/// строка редакции из журнала, внедрение текста, история редакций,
/// архивная плашка и резервные сообщения. Источник текстов — подмена
/// (FakePolicyContentSource), БД не затрагивается.
/// </summary>
public class PolicyPagesTests
{
    /// <summary>Контрольная сумма редакции для фейка (64 hex-символа).</summary>
    private const string Sha256V1 = "3f79bb7b435b05321651daefd374cdc681dc06faa725e8c590b8f1a3743f2f2a";

    /// <summary>Контрольная сумма второй редакции для фейка.</summary>
    private const string Sha256V2 = "a591a6d40ac051b7d9e9c1d3f3b8d8f7a2c4e6f8a0b2d4c6e8f0a2b4c6d8e0f2";

    /// <summary>Дата вступления первой редакции в силу (UTC, полдень).</summary>
    private static DateTimeOffset EffectiveFromV1 => new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Дата вступления второй редакции в силу (UTC, полдень).</summary>
    private static DateTimeOffset EffectiveFromV2 => new(2026, 11, 5, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Текст первой редакции cookie-политики для фейка.</summary>
    private const string CookieContentV1 = "<h2>1. Общие положения</h2><p>Обработка cookie регулируется 152-ФЗ.</p>";

    /// <summary>Текст второй редакции cookie-политики для фейка.</summary>
    private const string CookieContentV2 = "<h2>1. Общие положения</h2><p>Обработка cookie регулируется 152-ФЗ (редакция 2).</p>";

    /// <summary>Текст редакции политики персональных данных для фейка.</summary>
    private const string PersonalDataContent = "<h2>1. Общие положения</h2><p>Обработка персональных данных — 152-ФЗ.</p>";

    /// <summary>
    /// Рендерит страницу политик статически с подменённым источником текстов.
    /// </summary>
    /// <typeparam name="TPage">Страница политик (routable-компонент).</typeparam>
    /// <param name="source">Подмена IPolicyContentSource.</param>
    /// <param name="parameters">Параметры маршрута (для PolicyArchive);
    /// null — пустой набор (ParameterView.Empty).</param>
    /// <returns>HTML-разметка страницы.</returns>
    private static async Task<string> RenderPageAsync<TPage>(
        FakePolicyContentSource source,
        ParameterView? parameters = null)
        where TPage : IComponent
    {
        ServiceCollection services = new();
        services.AddLogging();
        // Кириллица, тире и знак номера не кодируются в HTML-entity: те же
        // диапазоны, что допускает кодировщик продакшн-рендера ASP.NET Core
        services.AddSingleton(HtmlEncoder.Create(UnicodeRanges.All));
        services.AddSingleton<WebShelf.Classes.Service.IPolicyContentSource>(source);

        await using ServiceProvider provider = services.BuildServiceProvider();
        await using HtmlRenderer renderer = new(provider, provider.GetRequiredService<ILoggerFactory>());

        return await renderer.Dispatcher.InvokeAsync(async () =>
        {
            HtmlRootComponent output = await renderer.RenderComponentAsync<TPage>(parameters ?? ParameterView.Empty);
            return output.ToHtmlString();
        });
    }

    /// <summary>
    /// Подмена источника с двумя редакциями cookie-политики: актуальная — №2.
    /// </summary>
    private static FakePolicyContentSource CreateCookieSourceWithTwoVersions()
    {
        PolicyVersion current = new(2, EffectiveFromV2, CookieContentV2, Sha256V2);
        PolicyVersion archived = new(1, EffectiveFromV1, CookieContentV1, Sha256V1);
        IReadOnlyList<PolicyVersionSummary> history =
        [
            new PolicyVersionSummary(2, EffectiveFromV2, Sha256V2),
            new PolicyVersionSummary(1, EffectiveFromV1, Sha256V1)
        ];

        return new FakePolicyContentSource(current, archived, history);
    }

    /// <summary>
    /// Страница cookie-политики рендерит оболочку, заголовок h1, строку
    /// редакции с номером и датой и внедрённый текст редакции.
    /// </summary>
    [Fact]
    public async Task CookiePolicyPage_RendersShellVersionLineAndContent()
    {
        FakePolicyContentSource source = CreateCookieSourceWithTwoVersions();

        string html = await RenderPageAsync<CookiePolicy>(source);

        Assert.Contains("ws-policy-titlebar", html);
        Assert.Contains("Политика обработки файлов cookie — WebShelf", html);
        Assert.Contains("<h1>Политика обработки и хранения файлов cookie</h1>", html);
        Assert.Contains("Редакция №2 от", html);
        Assert.Matches(new Regex("Редакция №2 от \\d{2}\\.\\d{2}\\.\\d{4}", RegexOptions.None, TimeSpan.FromSeconds(1)), html);
        Assert.Contains(CookieContentV2, html);
        Assert.Contains("Вернуться в систему", html);
        Assert.Contains("ws-policy-content", html);
    }

    /// <summary>
    /// Страница cookie-политики рендерит блок «История редакций»: обе
    /// редакции, пометку действующей и ссылку на архив первой редакции
    /// (/policy/cookie/1) с контрольной суммой.
    /// </summary>
    [Fact]
    public async Task CookiePolicyPage_RendersHistoryBlockWithArchiveLinks()
    {
        FakePolicyContentSource source = CreateCookieSourceWithTwoVersions();

        string html = await RenderPageAsync<CookiePolicy>(source);

        Assert.Contains("История редакций", html);
        Assert.Contains("№2", html);
        Assert.Contains("№1", html);
        Assert.Contains("действует", html);
        Assert.Contains("href=\"/policy/cookie/1\"", html);
        Assert.Contains(Sha256V1[..12], html);
    }

    /// <summary>
    /// При единственной редакции блок истории не выводится
    /// (журнал ещё не содержит изменений).
    /// </summary>
    [Fact]
    public async Task CookiePolicyPage_SingleVersion_NoHistoryBlock()
    {
        PolicyVersion current = new(1, EffectiveFromV1, CookieContentV1, Sha256V1);
        FakePolicyContentSource source = new(current, null,
        [
            new PolicyVersionSummary(1, EffectiveFromV1, Sha256V1)
        ]);

        string html = await RenderPageAsync<CookiePolicy>(source);

        Assert.DoesNotContain("История редакций", html);
        Assert.Contains("Редакция №1 от", html);
    }

    /// <summary>
    /// Пустой журнал (сбой синхронизации на живом экземпляре): страница
    /// рендерит резервное сообщение вместо текста, кнопка возврата сохранена.
    /// </summary>
    [Fact]
    public async Task CookiePolicyPage_EmptyJournal_ShowsFallbackMessage()
    {
        FakePolicyContentSource source = new();

        string html = await RenderPageAsync<CookiePolicy>(source);

        Assert.Contains("Текст политики временно недоступен", html);
        Assert.Contains("Вернуться в систему", html);
        Assert.DoesNotContain(CookieContentV1, html);
    }

    /// <summary>
    /// Страница политики персональных данных рендерит заголовок, строку
    /// редакции, внедрённый текст и кнопку возврата.
    /// </summary>
    [Fact]
    public async Task PersonalDataPolicyPage_RendersTitleVersionLineAndContent()
    {
        PolicyVersion current = new(1, EffectiveFromV1, PersonalDataContent, Sha256V1);
        FakePolicyContentSource source = new(current, null,
        [
            new PolicyVersionSummary(1, EffectiveFromV1, Sha256V1)
        ]);

        string html = await RenderPageAsync<PersonalDataPolicy>(source);

        Assert.Contains("Политика обработки персональных данных — WebShelf", html);
        Assert.Contains("<h1>Политика обработки персональных данных</h1>", html);
        Assert.Contains("Редакция №1 от", html);
        Assert.Contains(PersonalDataContent, html);
        Assert.Contains("Вернуться в систему", html);
    }

    /// <summary>
    /// Архивная страница (/policy/{code}/{version}) рендерит архивную плашку:
    /// номер, период действия, контрольная сумма и номер актуальной редакции.
    /// </summary>
    [Fact]
    public async Task PolicyArchivePage_OldVersion_RendersArchiveNote()
    {
        FakePolicyContentSource source = CreateCookieSourceWithTwoVersions();

        string html = await RenderPageAsync<PolicyArchive>(source,
            ParameterView.FromDictionary(new Dictionary<string, object?>
            {
                ["PolicyCode"] = "cookie",
                ["VersionNumber"] = 1
            }));

        Assert.Contains("Архивная редакция №1", html);
        Assert.Contains("не является действующей", html);
        Assert.Contains("Актуальная редакция — №2", html);
        Assert.Contains(Sha256V1, html);
        Assert.Contains(CookieContentV1, html);
        Assert.Contains("История редакций", html);
    }

    /// <summary>
    /// Архивная страница для номера актуальной редакции не выводит плашку —
    /// страница эквивалентна основной странице политики.
    /// </summary>
    [Fact]
    public async Task PolicyArchivePage_CurrentVersion_RendersWithoutArchiveNote()
    {
        FakePolicyContentSource source = CreateCookieSourceWithTwoVersions();

        string html = await RenderPageAsync<PolicyArchive>(source,
            ParameterView.FromDictionary(new Dictionary<string, object?>
            {
                ["PolicyCode"] = "cookie",
                ["VersionNumber"] = 2
            }));

        Assert.DoesNotContain("ws-policy-archive", html);
        Assert.Contains("Редакция №2 от", html);
        Assert.Contains(CookieContentV2, html);
    }

    /// <summary>
    /// Неизвестный код политики в маршруте — резервное сообщение
    /// «Политика с указанным кодом не существует».
    /// </summary>
    [Fact]
    public async Task PolicyArchivePage_UnknownPolicyCode_ShowsPolicyMissingMessage()
    {
        FakePolicyContentSource source = new();

        string html = await RenderPageAsync<PolicyArchive>(source,
            ParameterView.FromDictionary(new Dictionary<string, object?>
            {
                ["PolicyCode"] = "marketing",
                ["VersionNumber"] = 1
            }));

        Assert.Contains("Политика с указанным кодом не существует", html);
        Assert.Contains("Вернуться в систему", html);
    }

    /// <summary>
    /// Несуществующий номер редакции — резервное сообщение
    /// «Запрошенная редакция политики не найдена».
    /// </summary>
    [Fact]
    public async Task PolicyArchivePage_UnknownVersion_ShowsVersionMissingMessage()
    {
        FakePolicyContentSource source = CreateCookieSourceWithTwoVersions();

        string html = await RenderPageAsync<PolicyArchive>(source,
            ParameterView.FromDictionary(new Dictionary<string, object?>
            {
                ["PolicyCode"] = "cookie",
                ["VersionNumber"] = 9
            }));

        Assert.Contains("Запрошенная редакция политики не найдена", html);
        Assert.DoesNotContain(CookieContentV1, html);
    }

    /// <summary>
    /// Ни одна страница политики не выводит скриптов: CSP приложения
    /// (script-src 'self') запрещает встроенные теги script.
    /// </summary>
    [Fact]
    public async Task PolicyPages_NoScriptsInRenderedMarkup()
    {
        string html = await RenderPageAsync<CookiePolicy>(CreateCookieSourceWithTwoVersions());

        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
    }
}
