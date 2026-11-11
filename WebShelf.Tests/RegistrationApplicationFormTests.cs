using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.Web.HtmlRendering;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WebShelf.Classes.Service;
using WebShelf.Components.Shared;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты формы заявки на регистрацию (RegistrationApplicationForm):
/// состав обязательных полей, маска телефона, чек-боксы согласий со ссылками
/// на политики (персональные данные, cookie) и кнопка «Подать заявку» —
/// по умолчанию неактивна, включается только при полностью корректной форме
/// (RegistrationFormValidator.IsApplicationValid + подтверждённая проверкой
/// в БД уникальность e-mail и телефона). Рендер выполняется через
/// HtmlRenderer (статический SSR): проверяется исходная разметка до касания
/// полей (ошибки валидации не показываются; проверки уникальности
/// выполняются только после blur). Сервис заявок подменяется фейком —
/// обращения к БД в рендер-тестах исключены.
/// </summary>
public class RegistrationApplicationFormTests
{
    /// <summary>
    /// Подделка сервиса заявок (IRegistrationRequestService) для рендер-тестов:
    /// все контакты свободны, подача не выполняется (в статическом рендере
    /// обработчики не вызываются).
    /// </summary>
    private sealed class FakeRegistrationRequestService : IRegistrationRequestService
    {
        /// <summary>Проверка контактов: всегда свободны.</summary>
        public Task<RegistrationContactCheckResult> CheckContactsAsync(
            string email,
            string phone,
            CancellationToken cancellationToken = default)
            => Task.FromResult(RegistrationContactCheckResult.None);

        /// <summary>Подача заявки: не выполняется в статическом рендере.</summary>
        public Task<RegistrationSubmitResult> SubmitAsync(
            RegistrationApplication application,
            CancellationToken cancellationToken = default)
            => Task.FromResult(RegistrationSubmitResult.FromStatus(RegistrationSubmitStatus.ServerError));
    }

    /// <summary>
    /// Рендерит форму через HtmlRenderer и возвращает разметку. Форме
    /// предоставляются подмена сервиса заявок (IRegistrationRequestService)
    /// и параметр Permit (пермит, по которому открыто окно заявки);
    /// интерактивные обработчики (@bind, @onblur, @onclick) в статическом
    /// рендере не требуют JS interop.
    /// </summary>
    private static async Task<string> RenderFormAsync()
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddSingleton<IRegistrationRequestService>(new FakeRegistrationRequestService());

        await using ServiceProvider provider = services.BuildServiceProvider();
        await using HtmlRenderer renderer = new(provider, provider.GetRequiredService<ILoggerFactory>());

        return await renderer.Dispatcher.InvokeAsync(async () =>
        {
            HtmlRootComponent output = await renderer.RenderComponentAsync<RegistrationApplicationForm>(
                ParameterView.FromDictionary(new Dictionary<string, object?>
                {
                    ["Permit"] = "test-permit"
                }));

            // Кириллица из Razor-выражений (текст кнопки) кодируется числовыми
            // ссылками (&#x41F;...) — текст узлов декодируется перед проверками
            return System.Net.WebUtility.HtmlDecode(output.ToHtmlString());
        });
    }

    /// <summary>
    /// Форма содержит все обязательные поля: фамилия, имя, отчество, e-mail,
    /// номер телефона и оба чек-бокса согласий (все input помечены required).
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

        // Все семь элементов ввода обязательны к заполнению:
        // 5 текстовых полей + 2 чек-бокса согласий
        int requiredCount = CountOccurrences(html, "required");
        Assert.True(requiredCount >= 7, $"Ожидалось не менее 7 атрибутов required, найдено {requiredCount}");
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
    public async Task Render_Form_PersonalDataConsentCheckboxWithPolicyLink()
    {
        string html = await RenderFormAsync();

        Assert.Contains("id=\"pdConsent\"", html);
        Assert.Contains("152-ФЗ", html);
        Assert.Contains("href=\"/personal-data-policy.html\"", html);
        Assert.Contains("target=\"_blank\"", html);
        Assert.Contains("Политикой обработки персональных данных", html);
    }

    /// <summary>
    /// Чек-бокс согласия на обработку файлов cookie: обязателен, подпись
    /// ссылается на политику обработки файлов cookie (страница
    /// /cookie-policy.html, новая вкладка) — правила обработки аналогичны
    /// согласию на обработку персональных данных.
    /// </summary>
    [Fact]
    public async Task Render_Form_CookieConsentCheckboxWithPolicyLink()
    {
        string html = await RenderFormAsync();

        Assert.Contains("id=\"cookieConsent\"", html);
        Assert.Contains("href=\"/cookie-policy.html\"", html);
        Assert.Contains("Политикой обработки файлов cookie", html);
        Assert.Contains("обработку файлов cookie", html);
    }

    /// <summary>
    /// Кнопка «Подать заявку» по умолчанию неактивна: включается только
    /// когда вся форма заполнена корректно (все поля валидны, оба согласия
    /// даны, уникальность контактов подтверждена). В исходном (пустом)
    /// состоянии формы кнопка заблокирована атрибутом disabled.
    /// </summary>
    [Fact]
    public async Task Render_Form_SubmitButtonDisabledWhenFormEmpty()
    {
        string html = await RenderFormAsync();

        Assert.Contains("Подать заявку", html);
        Assert.Contains("<button type=\"button\" class=\"ws-btn-primary\" disabled>Подать заявку</button>", html);
    }

    /// <summary>
    /// Кнопка «Подать заявку» не отправляет HTML-форму: type="button",
    /// обработка выполняется в цепи Blazor (SubmitApplicationAsync) —
    /// как проверка пермита в окне активации, без полной навигации.
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
    /// после первого касания поля; предупреждения о занятых контактах —
    /// после проверки в БД).
    /// </summary>
    [Fact]
    public async Task Render_Form_NoFieldErrorsInitially()
    {
        string html = await RenderFormAsync();

        Assert.DoesNotContain("ws-field-error", html);
        Assert.DoesNotContain("ws-input-invalid", html);
        Assert.DoesNotContain("ws-message-error", html);
    }

    /// <summary>
    /// До подачи заявки сообщение об успешной подаче не показывается
    /// (форма заменяется им только после успешной записи заявки).
    /// </summary>
    [Fact]
    public async Task Render_Form_NoSuccessMessageInitially()
    {
        string html = await RenderFormAsync();

        Assert.DoesNotContain("ws-message-success", html);
        Assert.DoesNotContain("Заявка принята", html);
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
