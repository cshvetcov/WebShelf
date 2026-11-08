using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты статичной страницы политики обработки персональных данных
/// (wwwroot/personal-data-policy.html): страница — часть поставки, отдаётся
/// веб-сервером как есть и обязана соответствовать тем же правилам, что
/// и страница политики обработки cookie (WebShelfDocs/Решения в проекте/
/// Обработка персональных данных.md): без скриптов (CSP script-src 'self'),
/// русская локаль, noindex, ссылка возврата в систему, пометки для оператора.
/// </summary>
public class PersonalDataPolicyPageTests
{
    /// <summary>
    /// Каталог wwwroot проекта WebShelf: ищется от каталога сборки вверх
    /// до корня решения (WebShelf.slnx) — wwwroot не копируется в вывод сборки.
    /// </summary>
    private static string WwwrootPath
    {
        get
        {
            DirectoryInfo? directory = new(AppContext.BaseDirectory);

            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "WebShelf.slnx")))
            {
                directory = directory.Parent;
            }

            return directory is null
                ? throw new InvalidOperationException(
                    $"Корень решения не найден от {AppContext.BaseDirectory}: тест требует запуска из дерева репозитория.")
                : Path.Combine(directory.FullName, "WebShelf", "wwwroot");
        }
    }

    /// <summary>Содержимое страницы политики (UTF-8).</summary>
    private static async Task<string> ReadPolicyPageAsync()
    {
        string path = Path.Combine(WwwrootPath, "personal-data-policy.html");
        Assert.True(File.Exists(path), $"Страница политики не найдена: {path}");
        return await File.ReadAllTextAsync(path);
    }

    /// <summary>
    /// Страница существует в wwwroot и отдаётся по адресу
    /// /personal-data-policy.html (статичный файл, а не Razor-компонент).
    /// </summary>
    [Fact]
    public void PolicyPage_ExistsInWwwrootAsStaticFile()
    {
        string path = Path.Combine(WwwrootPath, "personal-data-policy.html");

        Assert.True(File.Exists(path), $"Страница политики не найдена: {path}");
    }

    /// <summary>
    /// Страница на русском языке (lang="ru") и закрыта от индексации (noindex):
    /// политика — служебный документ, а не публичный контент для поисковых систем.
    /// </summary>
    [Fact]
    public async Task PolicyPage_RussianLanguageAndNoIndex()
    {
        string html = await ReadPolicyPageAsync();

        Assert.Contains("<html lang=\"ru\"", html);
        Assert.Contains("noindex", html);
    }

    /// <summary>
    /// Страница не содержит скриптов: CSP приложения (script-src 'self')
    /// запрещает встроенные теги script — документ обязан оставаться без них
    /// (то же правило, что у страницы политики обработки cookie).
    /// Проверяются элементы разметки: HTML-комментарии-документации, в которых
    /// упомянуты теги script как текст, исключаются из проверки.
    /// </summary>
    [Fact]
    public async Task PolicyPage_NoScripts()
    {
        string html = await ReadPolicyPageAsync();

        string withoutComments = System.Text.RegularExpressions.Regex.Replace(
            html, @"<!--.*?-->", string.Empty, System.Text.RegularExpressions.RegexOptions.Singleline);

        Assert.DoesNotContain("<script", withoutComments, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Страница озаглавлена «Политика обработки персональных данных»
    /// и ссылается на 152-ФЗ — правовое основание обработки.
    /// </summary>
    [Fact]
    public async Task PolicyPage_HasTitleAndLegalBasis()
    {
        string html = await ReadPolicyPageAsync();

        Assert.Contains("Политика обработки персональных данных", html);
        Assert.Contains("152-ФЗ", html);
    }

    /// <summary>
    /// Страница содержит кнопку возврата в систему (ссылку на корень «/») —
    /// поведение аналогично странице политики обработки cookie.
    /// </summary>
    [Fact]
    public async Task PolicyPage_HasBackLinkToSystem()
    {
        string html = await ReadPolicyPageAsync();

        Assert.Contains("Вернуться в систему", html);
        Assert.Contains("href=\"/\"", html);
    }

    /// <summary>
    /// Раздел «Контакты оператора» содержит пометки «ЗАПОЛНИТЬ ПРИ
    /// РАЗВЁРТЫВАНИИ»: оператор обязан заполнить реквизиты при развёртывании
    /// (как на странице политики обработки cookie).
    /// </summary>
    [Fact]
    public async Task PolicyPage_HasFillOnDeploymentPlaceholders()
    {
        string html = await ReadPolicyPageAsync();

        Assert.Contains("ЗАПОЛНИТЬ ПРИ РАЗВЁРТЫВАНИИ", html);
        Assert.Contains("ws-fill-hint", html);
    }

    /// <summary>
    /// Страница оформлена в визуальном языке WebShelf — те же классы разметки,
    /// что у страницы политики обработки cookie (ws-policy, ws-policy-titlebar,
    /// ws-policy-content, ws-policy-back).
    /// </summary>
    [Fact]
    public async Task PolicyPage_UsesSameStyleVocabularyAsCookiePolicy()
    {
        string html = await ReadPolicyPageAsync();

        Assert.Contains("ws-policy-titlebar", html);
        Assert.Contains("ws-policy-content", html);
        Assert.Contains("ws-policy-back", html);
    }

    /// <summary>
    /// Страница описывает порядок отзыва согласия (ч. 2 ст. 9 152-ФЗ) —
    /// обязательный элемент информированности согласия, которое фиксируется
    /// чек-боксом формы заявки на регистрацию.
    /// </summary>
    [Fact]
    public async Task PolicyPage_DescribesConsentWithdrawal()
    {
        string html = await ReadPolicyPageAsync();

        Assert.Contains("отозвать согласие", html);
    }
}
