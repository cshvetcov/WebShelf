using Serilog;
using WebShelf.Classes.DC;
using WebShelf.Classes.Service;

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
/// <see cref="Data.ReadConfigAsync"/>.
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
    /// (значения уже зашифрованы мастер-ключом).
    /// Если заданы <c>domainuser</c> и <c>domainpass</c> — значения шифруются мастер-ключом,
    /// записываются в <c>sdomainuser</c>/<c>sdomainpass</c>, открытые поля очищаются.
    /// </para>
    /// </summary>
    /// <param name="config">Словарь конфигурации (результат разбора Server.conf).</param>
    /// <param name="instanceIdShort">Короткий InstanceId (12 символов, нижний регистр)
    /// для имён AD-групп WebShelf-{id}-*.</param>
    /// <param name="credentialsWriter">Писатель защищённых учётных данных в Server.conf.</param>
    /// <returns>
    /// Готовый экземпляр <see cref="Domain"/> при успешной инициализации;
    /// <see langword="null"/> — при любой ошибке (отсутствие ключей,
    /// недоступность мастер-ключа, неуспешная расшифровка, недоступность домена).
    /// </returns>
    internal static Domain? TryInitDomain(
        Dictionary<string, string> config,
        string instanceIdShort,
        SecureCredentialsWriter credentialsWriter)
    {
        const string method = nameof(TryInitDomain);

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

            byte[]? masterKey = EncryptionService.EnsureMasterKey();
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

            bool hasSecureUser = config.TryGetValue("sdomainuser", out string? sUser) &&
                                 !string.IsNullOrWhiteSpace(sUser);
            bool hasSecurePass = config.TryGetValue("sdomainpass", out string? sPass) &&
                                 !string.IsNullOrWhiteSpace(sPass);

            if (hasSecureUser && hasSecurePass)
            {
                // Уже зашифрованные значения — используем их
                encryptedUser = sUser!.Trim();
                encryptedPass = sPass!.Trim();

                try
                {
                    plainUser = EncryptionService.Decrypt(encryptedUser, masterKey);
                    plainPass = EncryptionService.Decrypt(encryptedPass, masterKey);
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
                    encryptedUser = EncryptionService.Encrypt(plainUser, masterKey);
                    encryptedPass = EncryptionService.Encrypt(plainPass, masterKey);
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

            // В Domain передаём зашифрованные значения и короткий InstanceId
            // (имена AD-групп WebShelf-{id}-*) — Domain не зависит от хранилища Data
            Domain domain = new(domainName, instanceIdShort, encryptedUser, encryptedPass);

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
