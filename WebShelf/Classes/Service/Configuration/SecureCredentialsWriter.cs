using System.Text;

namespace WebShelf.Classes.Service.Configuration;

/// <summary>
/// Управляемая перезапись Server.conf: записывает зашифрованные учётные
/// данные (домен, БД, TLS-сертификат) с сохранением комментариев, порядка
/// посторонних строк и с атомарной заменой файла.
/// </summary>
/// <remarks>
/// Класс выделен из <see cref="Data"/> механическим переносом (шаг 6 дорожной
/// карты декомпозиции); правки при переносе — только константа
/// <c>Class=</c> в логах перенесённого кода (принцип 6 дорожной карты)
/// и перенос пути из свойства <see cref="Data"/> в конструктор (продолжение
/// улучшения У2 шага 0: путь внедряется, как в <see cref="ServerConfigParser"/>).
/// <para>
/// Процедура записи принимает уже зашифрованные значения и сама криптографию
/// не вызывает — доступна для тестов на любой платформе. Какую пару ключей
/// обслуживать, определяет параметр <see cref="CredentialKeys"/>; вызывают
/// запись инициализаторы секций конфигурации (пространство
/// <c>WebShelf.Classes.Service.Configuration.Sections</c>). Оркестрация
/// чтения и инициализации секций остаётся в <see cref="Data.ReadConfigAsync"/>.
/// </para>
/// </remarks>
internal sealed class SecureCredentialsWriter
{
    private const string ClassName = "WebShelf.Classes.Service.Configuration.SecureCredentialsWriter";

    /// <summary>
    /// Полный путь к перезаписываемому файлу конфигурации Server.conf.
    /// Внедряется конструктором и не меняется после создания писателя.
    /// </summary>
    private string ConfigFile { get; }

    /// <summary>
    /// Создаёт писателя для указанного файла конфигурации.
    /// </summary>
    /// <param name="configFile">
    /// Полный путь к файлу Server.conf. Производственный путь передаёт
    /// <see cref="Data"/> (своё свойство ConfigFile), юнит-тесты — пути
    /// временных файлов.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Путь равен <see langword="null"/>.
    /// </exception>
    internal SecureCredentialsWriter(string configFile)
    {
        ArgumentNullException.ThrowIfNull(configFile);

        ConfigFile = configFile;
    }

    /// <summary>
    /// Имена ключей конфигурации для пары учётных данных: зашифрованные
    /// (<c>s…user</c>/<c>s…pass</c>) и открытые (<c>…user</c>/<c>…pass</c>),
    /// плюс подписи для логов. Позволяет одной процедуре записи
    /// <see cref="WriteSecureCredentials"/> обслуживать домен, БД и TLS-сертификат.
    /// Для секретов без «пользовательской» половины (пароль PFX-сертификата)
    /// ключи имени передаются как <see langword="null"/>.
    /// </summary>
    /// <param name="SecureUserKey">Ключ зашифрованного имени учётной записи;
    /// <see langword="null"/>, если пара не содержит имени.</param>
    /// <param name="SecurePassKey">Ключ зашифрованного пароля учётной записи.</param>
    /// <param name="PlainUserKey">Ключ открытого имени учётной записи (очищается после переноса);
    /// <see langword="null"/>, если пара не содержит имени.</param>
    /// <param name="PlainPassKey">Ключ открытого пароля учётной записи (очищается после переноса).</param>
    /// <param name="OwnerLabel">Подпись владельца учётных данных для логов: "домена", "БД", "TLS-сертификата".</param>
    /// <remarks>
    /// Видимость <see langword="internal"/> — тестовая точка (шаг 0 дорожной
    /// карты декомпозиции): тип является параметром
    /// <see cref="WriteSecureCredentials"/> и перенесён вместе с ней из
    /// <see cref="Data"/> шагом 6.
    /// </remarks>
    internal readonly record struct CredentialKeys(
        string? SecureUserKey,
        string SecurePassKey,
        string? PlainUserKey,
        string? PlainPassKey,
        string OwnerLabel)
    {
        /// <summary>
        /// Подпись пары зашифрованных ключей для логов:
        /// "sdomainuser/sdomainpass", "sdbuser/sdbpass", "scertpass".
        /// </summary>
        internal string SecurePairLabel => SecureUserKey is null
            ? SecurePassKey
            : $"{SecureUserKey}/{SecurePassKey}";
    }

    /// <summary>
    /// Ключи конфигурации сервисной учётной записи домена.
    /// Видимость <see langword="internal"/> — тестовая точка (шаг 0 дорожной
    /// карты декомпозиции): characterization-тесты используют фактические
    /// наборы ключей, а не их копии.
    /// </summary>
    internal static readonly CredentialKeys DomainCredentialKeys =
        new("sdomainuser", "sdomainpass", "domainuser", "domainpass", "домена");

    /// <summary>
    /// Ключи конфигурации сервисной учётной записи БД.
    /// Видимость <see langword="internal"/> — по той же причине, что и
    /// <see cref="DomainCredentialKeys"/> (шаг 0 дорожной карты декомпозиции).
    /// </summary>
    internal static readonly CredentialKeys DatabaseCredentialKeys =
        new("sdbuser", "sdbpass", "dbuser", "dbpass", "БД");

    /// <summary>
    /// Ключи конфигурации пароля PFX-сертификата TLS (без «пользовательской» половины).
    /// Видимость <see langword="internal"/> — по той же причине, что и
    /// <see cref="DomainCredentialKeys"/> (шаг 0 дорожной карты декомпозиции).
    /// </summary>
    internal static readonly CredentialKeys TlsCredentialKeys =
        new(null, "scertpass", null, "certpass", "TLS-сертификата");

    /// <summary>
    /// Записывает зашифрованные учётные данные в Server.conf по общей процедуре:
    /// обновляет значения зашифрованных ключей, очищает открытые ключи,
    /// сохраняет комментарии и порядок остальных строк.
    /// </summary>
    /// <param name="keys">Имена ключей конфигурации и подписи для логов.</param>
    /// <param name="encryptedUser">Зашифрованное имя учётной записи (Base64);
    /// <see langword="null"/>, если пара не содержит имени (пароль PFX-сертификата).</param>
    /// <param name="encryptedPass">Зашифрованный пароль учётной записи (Base64).</param>
    /// <returns><see langword="true"/> при успешной записи; иначе <see langword="false"/>.</returns>
    /// <remarks>
    /// Видимость <see langword="internal"/> — тестовая точка (шаг 0 дорожной
    /// карты декомпозиции): characterization-тесты фиксируют фактическое
    /// поведение записи; шагом 6 вызов переписан с <see cref="Data"/> на
    /// вынесенный класс — контракт тот же, ожидания не менялись.
    /// Метод принимает уже зашифрованные значения и сам криптографию
    /// не вызывает — доступен для тестов на любой платформе.
    /// </remarks>
    internal bool WriteSecureCredentials(CredentialKeys keys, string? encryptedUser, string encryptedPass)
    {
        const string method = nameof(WriteSecureCredentials);

        try
        {
            if (!File.Exists(ConfigFile))
            {
                Log.Error(
                    "Файл конфигурации не найден при записи {Keys}. Class={Class}, Method={Method}, Path={Path}",
                    keys.SecurePairLabel, ClassName, method, ConfigFile);
                return false;
            }

            string[] lines = File.ReadAllLines(ConfigFile, Encoding.UTF8);
            List<string> result = new(lines.Length + 4);

            bool hasSecureUser = false;
            bool hasSecurePass = false;
            bool hasPlainUser = false;
            bool hasPlainPass = false;

            foreach (string line in lines)
            {
                string trimmed = line.Trim();

                if (trimmed.Length == 0 || trimmed[0] == '#')
                {
                    result.Add(line);
                    continue;
                }

                int eqIndex = trimmed.IndexOf('=');
                if (eqIndex <= 0)
                {
                    result.Add(line);
                    continue;
                }

                string key = trimmed[..eqIndex].Trim();

                if (keys.SecureUserKey is not null &&
                    key.Equals(keys.SecureUserKey, StringComparison.OrdinalIgnoreCase))
                {
                    result.Add($"{keys.SecureUserKey}={encryptedUser}");
                    hasSecureUser = true;
                }
                else if (key.Equals(keys.SecurePassKey, StringComparison.OrdinalIgnoreCase))
                {
                    result.Add($"{keys.SecurePassKey}={encryptedPass}");
                    hasSecurePass = true;
                }
                else if (keys.PlainUserKey is not null &&
                         key.Equals(keys.PlainUserKey, StringComparison.OrdinalIgnoreCase))
                {
                    // Открытый логин очищаем после переноса в зашифрованный ключ
                    result.Add($"{keys.PlainUserKey}=");
                    hasPlainUser = true;
                }
                else if (keys.PlainPassKey is not null &&
                         key.Equals(keys.PlainPassKey, StringComparison.OrdinalIgnoreCase))
                {
                    // Открытый пароль очищаем после переноса в зашифрованный ключ
                    result.Add($"{keys.PlainPassKey}=");
                    hasPlainPass = true;
                }
                else
                {
                    result.Add(line);
                }
            }

            if (keys.SecureUserKey is not null && !hasSecureUser)
                result.Add($"{keys.SecureUserKey}={encryptedUser}");
            if (!hasSecurePass)
                result.Add($"{keys.SecurePassKey}={encryptedPass}");
            if (keys.PlainUserKey is not null && !hasPlainUser)
                result.Add($"{keys.PlainUserKey}=");
            if (keys.PlainPassKey is not null && !hasPlainPass)
                result.Add($"{keys.PlainPassKey}=");

            // Атомарная подмена: запись во временный файл + File.Replace исключает
            // появление усечённого конфига при сбое питания или аварийном завершении.
            // Оставшийся после сбоя .tmp перезаписывается при следующей попытке
            string tempPath = ConfigFile + ".tmp";
            File.WriteAllLines(tempPath, result, Encoding.UTF8);
            File.Replace(tempPath, ConfigFile, destinationBackupFileName: null);

            Log.Information(
                "Зашифрованные учётные данные {Owner} записаны в конфигурацию. Class={Class}, Method={Method}",
                keys.OwnerLabel, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка записи {Keys}. Class={Class}, Method={Method}, Path={Path}",
                keys.SecurePairLabel, ClassName, method, ConfigFile);
            return false;
        }
    }

    /// <summary>
    /// Записывает зашифрованные <c>sdomainuser</c> и <c>sdomainpass</c> в Server.conf,
    /// очищает значения <c>domainuser</c> и <c>domainpass</c>.
    /// </summary>
    /// <param name="encryptedUser">Зашифрованное имя сервисной учётки (Base64).</param>
    /// <param name="encryptedPass">Зашифрованный пароль сервисной учётки (Base64).</param>
    /// <returns><see langword="true"/> при успешной записи; иначе <see langword="false"/>.</returns>
    /// <remarks>
    /// Видимость <see langword="internal"/> (в <see cref="Data"/> метод был
    /// закрытым): после выноса шагом 6 вызывается инициализатором секции
    /// домена из другого файла той же сборки.
    /// </remarks>
    internal bool WriteSecureDomainCredentials(string encryptedUser, string encryptedPass)
    {
        return WriteSecureCredentials(DomainCredentialKeys, encryptedUser, encryptedPass);
    }

    /// <summary>
    /// Записывает зашифрованные <c>sdbuser</c> и <c>sdbpass</c> в Server.conf,
    /// очищает значения <c>dbuser</c> и <c>dbpass</c>.
    /// </summary>
    /// <param name="encryptedUser">Зашифрованное имя сервисной учётки БД (Base64).</param>
    /// <param name="encryptedPass">Зашифрованный пароль сервисной учётки БД (Base64).</param>
    /// <returns><see langword="true"/> при успешной записи; иначе <see langword="false"/>.</returns>
    /// <remarks>
    /// Видимость <see langword="internal"/> (в <see cref="Data"/> метод был
    /// закрытым): после выноса шагом 6 вызывается инициализатором секции
    /// БД из другого файла той же сборки.
    /// </remarks>
    internal bool WriteSecureDbCredentials(string encryptedUser, string encryptedPass)
    {
        return WriteSecureCredentials(DatabaseCredentialKeys, encryptedUser, encryptedPass);
    }
}
