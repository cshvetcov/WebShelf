namespace WebShelf.Classes.Crypto;

/// <summary>
/// Контексты шифрования — метки назначения зашифрованных данных,
/// передаваемые в <see cref="CryptoEngine"/> и подмешиваемые в AAD GCM.
/// </summary>
/// <remarks>
/// Контекст привязывает шифроблоб к назначению: блоб, зашифрованный в одном
/// контексте, не расшифровывается в другом (сбой проверки тега), поэтому
/// перестановка зашифрованных значений между полями Server.conf или между
/// потребителями невозможна.
/// <para>
/// Значения являются частью замороженного криптоформата (см.
/// <see cref="CryptoEngine"/>): изменение строки контекста = смена контекста =
/// нечитаемость существующих данных. Для полей Server.conf контекст совпадает
/// с именем ключа конфигурации; для внутренних полей классов используется
/// полное имя класса-владельца.
/// </para>
/// </remarks>
internal static class CryptoContexts
{
    /// <summary>
    /// Зашифрованное имя сервисной учётной записи AD
    /// (Server.conf, ключ <c>sdomainuser</c>).
    /// </summary>
    internal const string DomainUser = "sdomainuser";

    /// <summary>
    /// Зашифрованный пароль сервисной учётной записи AD
    /// (Server.conf, ключ <c>sdomainpass</c>).
    /// </summary>
    internal const string DomainPassword = "sdomainpass";

    /// <summary>
    /// Зашифрованное имя сервисной учётной записи БД
    /// (Server.conf, ключ <c>sdbuser</c>).
    /// </summary>
    internal const string DatabaseUser = "sdbuser";

    /// <summary>
    /// Зашифрованный пароль сервисной учётной записи БД
    /// (Server.conf, ключ <c>sdbpass</c>).
    /// </summary>
    internal const string DatabasePassword = "sdbpass";

    /// <summary>
    /// Зашифрованный пароль PFX-сертификата
    /// (Server.conf, ключ <c>scertpass</c>).
    /// </summary>
    internal const string CertificatePassword = "scertpass";

    /// <summary>
    /// Внутреннее поле <see cref="WebShelf.Classes.DC.Domain"/>: имя сервисной
    /// учётной записи AD после нормализации (не хранится в Server.conf).
    /// </summary>
    internal const string DomainServiceUser = "WebShelf.Classes.DC.Domain.ServiceUser";

    /// <summary>
    /// Внутреннее поле <see cref="WebShelf.Classes.DC.Domain"/>: пароль
    /// сервисной учётной записи AD (не хранится в Server.conf).
    /// </summary>
    internal const string DomainServicePassword = "WebShelf.Classes.DC.Domain.ServicePassword";
}
