namespace WebShelf.Classes.Service;

/// <summary>
/// Каталог политик обработки данных, известных системе: коды журнала редакций,
/// файлы поставки и заголовки страниц. Единственный источник соответствия
/// «код — файл — заголовки»: сервис журнала, страницы политик и тесты
/// опираются только на него. Коды зафиксированы CHECK-ограничением
/// <c>webshelf.policy_versions_policy_domain</c> каркаса БД — добавление
/// новой политики требует синхронного расширения каркаса и каталога.
/// </summary>
internal static class PolicyCatalog
{
    /// <summary>Код политики обработки файлов cookie.</summary>
    internal const string CookiePolicyCode = "cookie";

    /// <summary>Код политики обработки персональных данных.</summary>
    internal const string PersonalDataPolicyCode = "personal-data";

    /// <summary>Подкаталог поставки с текстами политик (относительно каталога приложения).</summary>
    internal const string PoliciesRelativeDirectory = "Content/Policies";

    /// <summary>Политика обработки файлов cookie.</summary>
    private static readonly PolicyDefinition CookiePolicyDefinition = new(
        CookiePolicyCode,
        "cookie-policy.html",
        "Политика обработки и хранения файлов cookie",
        "Политика обработки файлов cookie — WebShelf");

    /// <summary>Политика обработки персональных данных.</summary>
    private static readonly PolicyDefinition PersonalDataPolicyDefinition = new(
        PersonalDataPolicyCode,
        "personal-data-policy.html",
        "Политика обработки персональных данных",
        "Политика обработки персональных данных — WebShelf");

    /// <summary>Политика обработки файлов cookie (страница /cookie-policy.html).</summary>
    internal static PolicyDefinition Cookie => CookiePolicyDefinition;

    /// <summary>Политика обработки персональных данных (страница /personal-data-policy.html).</summary>
    internal static PolicyDefinition PersonalData => PersonalDataPolicyDefinition;

    /// <summary>Все известные политики.</summary>
    internal static readonly IReadOnlyList<PolicyDefinition> Policies =
    [
        CookiePolicyDefinition,
        PersonalDataPolicyDefinition
    ];

    /// <summary>
    /// Ищет политику по коду журнала редакций.
    /// </summary>
    /// <param name="code">Код политики (сравнение точное, регистр значим).</param>
    /// <returns>Описание политики или <see langword="null"/>, если код неизвестен.</returns>
    /// <exception cref="ArgumentNullException">
    /// Возникает, если <paramref name="code"/> равен <see langword="null"/>.
    /// </exception>
    internal static PolicyDefinition? TryFind(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        return Policies.FirstOrDefault(policy => string.Equals(policy.Code, code, StringComparison.Ordinal));
    }
}
