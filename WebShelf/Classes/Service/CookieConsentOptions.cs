namespace WebShelf.Classes.Service;

/// <summary>
/// Параметры инфраструктуры согласия на обработку файлов cookie из Server.conf.
/// Ключ <c>cookieconsent</c> включает баннер согласия (компонент
/// <c>WebShelf.Components.Shared.CookieConsent</c>). По умолчанию баннер
/// выключен: система использует только технически необходимые cookie,
/// для которых отдельное согласие не требуется (правовой анализ —
/// WebShelfDocs/Решения в проекте/Обработка cookie.md).
/// </summary>
/// <param name="BannerEnabled">
/// <see langword="true"/> — баннер согласия показывается пользователям
/// при отсутствии сохранённого решения; <see langword="false"/>
/// (безопасное значение по умолчанию) — баннер скрыт.
/// </param>
internal sealed record CookieConsentOptions(bool BannerEnabled)
{
    private const string ClassName = "WebShelf.Classes.Service.CookieConsentOptions";

    /// <summary>
    /// Разбирает параметры из словаря конфигурации Server.conf.
    /// Ключ <c>cookieconsent</c> опционален: его отсутствие — не ошибка
    /// (баннер выключен). Некорректное значение заменяется безопасным
    /// <see langword="false"/> с предупреждением в лог.
    /// </summary>
    /// <param name="config">Словарь конфигурации (ключи без учёта регистра).</param>
    /// <returns>Параметры инфраструктуры согласия; никогда не <see langword="null"/>.</returns>
    internal static CookieConsentOptions Create(Dictionary<string, string> config)
    {
        const string method = nameof(Create);

        ArgumentNullException.ThrowIfNull(config);

        bool bannerEnabled = false;

        if (config.TryGetValue("cookieconsent", out string? consentValue) && !string.IsNullOrWhiteSpace(consentValue))
        {
            if (!bool.TryParse(consentValue.Trim(), out bannerEnabled))
            {
                Log.Warning(
                    "Некорректное значение cookieconsent={ConsentValue}: используется безопасное значение false. Class={Class}, Method={Method}",
                    consentValue, ClassName, method);
                bannerEnabled = false;
            }
        }

        Log.Information(
            "Параметры согласия на обработку cookie установлены. BannerEnabled={BannerEnabled}. Class={Class}, Method={Method}",
            bannerEnabled, ClassName, method);

        return new CookieConsentOptions(bannerEnabled);
    }
}
