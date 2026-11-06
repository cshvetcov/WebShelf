using WebShelf.Classes.Crypto;
using WebShelf.Classes.DC;

namespace WebShelf.Classes.Service.Configuration.Sections;

/// <summary>
/// Инициализатор секции домена Active Directory: читает параметры домена
/// и сервисной учётной записи из словаря конфигурации, выполняет миграцию
/// открытых учётных данных в защищённые и проверяет доступность
/// контроллера домена.
/// </summary>
/// <remarks>
/// Класс выделен из <c>Data</c> механическим переносом (шаг 6 дорожной
/// карты декомпозиции, точка решения о секциях: <c>Data</c> после выноса
/// записи остаётся больше ~550 строк). Правки при переносе — константа
/// <c>Class=</c> в логах перенесённого кода (принцип 6 дорожной карты)
/// и возврат результата вместо мутации состояния <c>Data</c>: метод
/// возвращает готовый экземпляр <see cref="Domain"/> либо
/// <see langword="null"/>, присваивание свойству выполняет оркестратор
/// <see cref="Data.ReadConfigAsync"/>. Шаг 8 дорожной карты (улучшение У3):
/// криптография поступает параметрами как инстансные зависимости
/// <see cref="KeyStore"/> и <see cref="CryptoEngine"/> вместо статических
/// вызовов фасада — поведение не менялось.
/// </remarks>
internal static class DomainSection
{
    private const string ClassName = "WebShelf.Classes.Service.Configuration.Sections.DomainSection";

    /// <summary>
    /// Обязательные ключи домена в конфигурации. Учётные данные берутся из
    /// <c>sdomainuser</c>/<c>sdomainpass</c> либо из <c>domainuser</c>/<c>domainpass</c>.
    /// </summary>
    private static readonly string[] RequiredDomainKeys = ["domainname"];

    /// <summary>
    /// Инициализирует домен из словаря конфигурации и проверяет доступность
    /// контроллера домена через сервисную учётную запись (без проверки
    /// группы Users).
    /// <para>
    /// Если заданы <c>sdomainuser</c> и <c>sdomainpass</c> — используются они
    /// (значения уже зашифрованы мастер-ключом); непустые остаточные открытые
    /// <c>domainuser</c>/<c>domainpass</c> при этом затираются (улучшение У1
    /// дорожной карты декомпозиции — симметрия с парами БД и TLS).
    /// Если заданы <c>domainuser</c> и <c>domainpass</c> — значения шифруются мастер-ключом,
    /// записываются в <c>sdomainuser</c>/<c>sdomainpass</c>, открытые поля очищаются.
    /// </para>
    /// </summary>
    /// <param name="config">Словарь конфигурации (результат разбора Server.conf).</param>
    /// <param name="instanceIdShort">Короткий InstanceId (12 символов, нижний регистр)
    /// для имён AD-групп WebShelf-{id}-*.</param>
    /// <param name="credentialsWriter">Писатель защищённых учётных данных в Server.conf.</param>
    /// <param name="keyStore">Хранилище ключей — источник мастер-ключа
    /// (в Production — singleton из DI; улучшение У3 дорожной карты декомпозиции).</param>
    /// <param name="cryptoEngine">Криптографический движок — шифрование и
    /// расшифровка учётных данных (в Production — singleton из DI).</param>
    /// <returns>
    /// Готовый экземпляр <see cref="Domain"/> при успешной инициализации;
    /// <see langword="null"/> — при любой ошибке (отсутствие ключей,
    /// недоступность мастер-ключа, неуспешная расшифровка, недоступность домена).
    /// </returns>
    internal static Domain? TryInitDomain(
        Dictionary<string, string> config,
        string instanceIdShort,
        SecureCredentialsWriter credentialsWriter,
        KeyStore keyStore,
        CryptoEngine cryptoEngine)
    {
        const string method = nameof(TryInitDomain);

        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentNullException.ThrowIfNull(cryptoEngine);

        try
        {
            string[] keys = RequiredDomainKeys;

            if (!keys.All(config.ContainsKey))
            {
                IEnumerable<string> missing = keys.Where(k => !config.ContainsKey(k));
                Log.Error(
                    "Отсутствуют обязательные ключи домена: {MissingKeys}. Class={Class}, Method={Method}",
                    string.Join(", ", missing), ClassName, method);
                return null;
            }

            string domainName = config["domainname"];

            if (string.IsNullOrWhiteSpace(domainName))
            {
                Log.Error(
                    "Значение domainname пустое. Class={Class}, Method={Method}",
                    ClassName, method);
                return null;
            }

            byte[]? masterKey = keyStore.EnsureMasterKey();
            if (masterKey is null)
            {
                Log.Error(
                    "Мастер-ключ недоступен при инициализации домена. Class={Class}, Method={Method}",
                    ClassName, method);
                return null;
            }

            string encryptedUser;
            string encryptedPass;
            string plainUser;
            string plainPass;

            string? secureUser = config.TryGetValue("sdomainuser", out string? sUser) &&
                                 !string.IsNullOrWhiteSpace(sUser)
                ? sUser
                : null;
            string? securePass = config.TryGetValue("sdomainpass", out string? sPass) &&
                                 !string.IsNullOrWhiteSpace(sPass)
                ? sPass
                : null;

            if (secureUser is not null && securePass is not null)
            {
                // Уже зашифрованные значения — используем их
                encryptedUser = secureUser.Trim();
                encryptedPass = securePass.Trim();

                try
                {
                    plainUser = cryptoEngine.Decrypt(encryptedUser, masterKey, CryptoContexts.DomainUser);
                    plainPass = cryptoEngine.Decrypt(encryptedPass, masterKey, CryptoContexts.DomainPassword);
                }
                catch (Exception ex)
                {
                    Log.Error(ex,
                        "Не удалось расшифровать sdomainuser/sdomainpass. Class={Class}, Method={Method}",
                        ClassName, method);
                    return null;
                }

                if (string.IsNullOrWhiteSpace(plainUser) || string.IsNullOrWhiteSpace(plainPass))
                {
                    Log.Error(
                        "После расшифровки sdomainuser/sdomainpass получены пустые значения. Class={Class}, Method={Method}",
                        ClassName, method);
                    return null;
                }

                Log.Information(
                    "Учётные данные домена загружены из sdomainuser/sdomainpass. Class={Class}, Method={Method}",
                    ClassName, method);

                // Остаточные открытые domainuser/domainpass подлежат очистке: секреты
                // не должны оставаться в конфигурации в незашифрованном виде
                // (улучшение У1 дорожной карты декомпозиции, шаг 6 — симметрия
                // с парами БД и TLS, затирающими остаточные открытые значения)
                config.TryGetValue("domainuser", out string? leftoverUser);
                config.TryGetValue("domainpass", out string? leftoverPass);

                bool hasPlainLeftovers =
                    !string.IsNullOrWhiteSpace(leftoverUser) ||
                    !string.IsNullOrWhiteSpace(leftoverPass);

                if (hasPlainLeftovers)
                {
                    if (credentialsWriter.WriteSecureDomainCredentials(encryptedUser, encryptedPass))
                    {
                        Log.Information(
                            "Остаточные открытые domainuser/domainpass очищены в конфигурации. Class={Class}, Method={Method}",
                            ClassName, method);
                    }
                    else
                    {
                        Log.Warning(
                            "Не удалось очистить остаточные открытые domainuser/domainpass. Class={Class}, Method={Method}",
                            ClassName, method);
                    }
                }
            }
            else
            {
                // Открытые domainuser/domainpass — шифруем и сохраняем в sdomain*
                if (!config.TryGetValue("domainuser", out string? domainUser) ||
                    !config.TryGetValue("domainpass", out string? domainPass) ||
                    string.IsNullOrWhiteSpace(domainUser) ||
                    string.IsNullOrWhiteSpace(domainPass))
                {
                    Log.Error(
                        "Отсутствуют domainuser/domainpass и sdomainuser/sdomainpass. Class={Class}, Method={Method}",
                        ClassName, method);
                    return null;
                }

                plainUser = domainUser.Trim();
                plainPass = domainPass.Trim();

                try
                {
                    encryptedUser = cryptoEngine.Encrypt(plainUser, masterKey, CryptoContexts.DomainUser);
                    encryptedPass = cryptoEngine.Encrypt(plainPass, masterKey, CryptoContexts.DomainPassword);
                }
                catch (Exception ex)
                {
                    Log.Error(ex,
                        "Не удалось зашифровать domainuser/domainpass. Class={Class}, Method={Method}",
                        ClassName, method);
                    return null;
                }

                if (!credentialsWriter.WriteSecureDomainCredentials(encryptedUser, encryptedPass))
                {
                    Log.Error(
                        "Не удалось записать sdomainuser/sdomainpass в конфигурацию. Class={Class}, Method={Method}",
                        ClassName, method);
                    return null;
                }

                Log.Information(
                    "Учётные данные домена зашифрованы и сохранены в sdomainuser/sdomainpass. Class={Class}, Method={Method}",
                    ClassName, method);
            }

            // В Domain передаём зашифрованные значения, короткий InstanceId
            // (имена AD-групп WebShelf-{id}-*) и криптографические зависимости —
            // Domain не зависит от хранилища Data
            Domain domain = new(domainName, instanceIdShort, encryptedUser, encryptedPass, keyStore, cryptoEngine);

            Log.Information(
                "Домен инициализирован. Domain={Domain}, User={User}. Class={Class}, Method={Method}",
                domain.Name, "SystemAccount", ClassName, method);

            // Проверка доступности AD: валидация сервисной учётки без проверки группы Users (открытый пароль)
            bool isAvailable = domain.ValidateAdCredentials(plainUser, plainPass, checkUsersGroup: false);
            if (!isAvailable)
            {
                Log.Error(
                    "Домен недоступен или сервисная учётная запись невалидна. Domain={Domain}, User={User}. Class={Class}, Method={Method}",
                    domain.Name, "SystemAccount", ClassName, method);
                return null;
            }

            Log.Information(
                "Доступность домена подтверждена. Domain={Domain}. Class={Class}, Method={Method}",
                domain.Name, ClassName, method);

            return domain;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка инициализации домена. Class={Class}, Method={Method}",
                ClassName, method);
            return null;
        }
    }
}
