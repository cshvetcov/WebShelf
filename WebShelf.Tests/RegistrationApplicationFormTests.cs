using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.Web.HtmlRendering;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WebShelf.Components.Shared;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты формы заявки на регистрацию (RegistrationApplicationForm):
/// состав обязательных полей, маска телефона, чек-бокс согласия со ссылкой
/// на политику обработки персональных данных и кнопка «Подать заявку» —
/// по умолчанию неактивна, включается только при полностью корректной
/// форме (RegistrationFormValidator.IsApplicationValid); обработка
/// нажатия по задаче отсутствует. Рендер выполняется через HtmlRenderer
/// (статический SSR): проверяется исходная разметка до касания полей
/// (ошибки валидации не показываются).
/// </summary>
public class RegistrationApplicationFormTests
{
    /// <summary>
    /// Рендерит форму через HtmlRenderer и возвращает разметку.
    /// Форма — самодостаточный компонент без параметров и инжекций;
    /// интерактивные обработчики (@bind, @onblur) в статическом рендере
    /// не требуют JS interop.
    /// </summary>
    private static async Task<string> RenderFormAsync()
    {
        ServiceCollection services = new();
        services.AddLogging();

        await using ServiceProvider provider = services.BuildServiceProvider();
        await using HtmlRenderer renderer = new(provider, provider.GetRequiredService<ILoggerFactory>());

        return await renderer.Dispatcher.InvokeAsync(async () =>
        {
            HtmlRootComponent output = await renderer.RenderComponentAsync<RegistrationApplicationForm>();
            return output.ToHtmlString();
        });
    }

    /// <summary>
    /// Форма содержит все обязательные поля: фамилия, имя, отчество, e-mail,
    /// номер телефона (все input помечены required).
    /// </summary>
    [Fact]
    public async Task Render_Form_ContainsAllRequiredFields()
    {
        string html = await RenderFormAsync();

        Assert.Contains("Фамилия", html);
        Assert.Contains("id=\"lastName\"", html);

        Assert.Contains("Имя", html);
        Assert.Contains("id=\"firstName\"", html);

        Assert.Contains("Отчество", html);
        Assert.Contains("id=\"patronymic\"", html);

        Assert.Contains("E-Mail", html);
        Assert.Contains("id=\"email\"", html);

        Assert.Contains("Номер телефона", html);
        Assert.Contains("id=\"phone\"", html);

        // Все шесть элементов ввода обязательны к заполнению
        int requiredCount = CountOccurrences(html, "required");
        Assert.True(requiredCount >= 6, $"Ожидалось не менее 6 атрибутов required, найдено {requiredCount}");
    }

    /// <summary>
    /// Автоматическая проверка форматов: поле e-mail имеет тип email,
    /// поле телефона — тип tel с плейсхолдером формата +7 (XXX) XXX-XX-XX
    /// (в статическом рендере атрибуты HTML-кодируются: «+» выводится как
    /// символьная ссылка &#x2B;, поэтому проверяется неизменяемая часть маски).
    /// </summary>
    [Fact]
    public async Task Render_Form_EmailAndPhoneInputsHaveProperTypes()
    {
        string html = await RenderFormAsync();

        Assert.Contains("type=\"email\"", html);
        Assert.Contains("type=\"tel\"", html);
        Assert.Contains("(XXX) XXX-XX-XX", html);
    }

    /// <summary>
    /// Чек-бокс согласия на обработку персональных данных: подпись содержит
    /// упоминание 152-ФЗ и ссылку на политику (статичная страница
    /// /personal-data-policy.html, открывается в новой вкладке — уход
    /// со страницы не должен терять введённые данные).
    /// </summary>
    [Fact]
    public async Task Render_Form_ConsentCheckboxWithPolicyLink()
    {
        string html = await RenderFormAsync();

        Assert.Contains("id=\"pdConsent\"", html);
        Assert.Contains("type=\"checkbox\"", html);
        Assert.Contains("152-ФЗ", html);
        Assert.Contains("href=\"/personal-data-policy.html\"", html);
        Assert.Contains("target=\"_blank\"", html);
        Assert.Contains("Политикой обработки персональных данных", html);
    }

    /// <summary>
    /// Кнопка «Подать заявку» по умолчанию неактивна: включается только
    /// когда вся форма заполнена корректно (все поля валидны и дано
    /// согласие). В исходном (пустом) состоянии формы кнопка заблокирована
    /// атрибутом disabled.
    /// </summary>
    [Fact]
    public async Task Render_Form_SubmitButtonDisabledWhenFormEmpty()
    {
        string html = await RenderFormAsync();

        Assert.Contains("Подать заявку", html);
        Assert.Contains("<button type=\"button\" class=\"ws-btn-primary\" disabled>Подать заявку</button>", html);
    }

    /// <summary>
    /// Кнопка «Подать заявку» не отправляет форму: type="button" и без
    /// обработчика (по задаче поведение при нажатии отсутствует — обработка
    /// отправки появится вместе с логикой регистрации).
    /// </summary>
    [Fact]
    public async Task Render_Form_SubmitButtonIsButtonNotSubmit()
    {
        string html = await RenderFormAsync();

        Assert.Contains("type=\"button\"", html);
        Assert.DoesNotContain("type=\"submit\"", html);
    }

    /// <summary>
    /// До касания полей ошибки валидации не показываются: пользователь
    /// видит чистую форму (ошибки появляются автоматически по мере ввода
    /// после первого касания поля).
    /// </summary>
    [Fact]
    public async Task Render_Form_NoFieldErrorsInitially()
    {
        string html = await RenderFormAsync();

        Assert.DoesNotContain("ws-field-error", html);
        Assert.DoesNotContain("ws-input-invalid", html);
    }

    /// <summary>
    /// Подсчитывает количество вхождений подстроки в разметку.
    /// </summary>
    private static int CountOccurrences(string html, string fragment)
    {
        int count = 0;
        int index = html.IndexOf(fragment, StringComparison.Ordinal);

        while (index >= 0)
        {
            count++;
            index = html.IndexOf(fragment, index + fragment.Length, StringComparison.Ordinal);
        }

        return count;
    }
}
