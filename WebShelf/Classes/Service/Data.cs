using System.Text;
using Npgsql;
using Serilog;
using WebShelf.Classes.DC;
using WebShelf.Classes.DB;

namespace WebShelf.Classes.Service;

/// <summary>
/// Центральное хранилище системных данных приложения WebShelf.
/// Отвечает за чтение конфигурации (Server.conf) и предоставление
/// экземпляра домена Active Directory, подключения к PostgreSQL,
/// InstanceId, порта и схемы (http/https).
/// </summary>
internal static class Data
{
    private const string ClassName = "WebShelf.Classes.Service.Data";

    /// <summary>
    /// Порт, на котором слушает HTTP(S)-сервер.
    /// <see langword="null"/>, если не задан или некорректен.
    /// </summary>
    internal static int? Port { get; private set; }

    /// <summary>
    /// Схема прослушивания: <c>http</c> или <c>https</c>.
    /// <see langword="null"/>, если не задана или некорректна.
    /// </summary>
    internal static string? Scheme { get; private set; }

    /// <summary>
    /// Полный путь к файлу конфигурации Server.conf.
    /// </summary>
    internal static string ConfigFile { get; } =
        Path.Combine(AppContext.BaseDirectory, "Server.conf");

    /// <summary>
    /// Экземпляр домена Active Directory.
    /// <see langword="null"/>, если конфигурация не загружена или неполная.
    /// </summary>
    internal static Domain? Domain { get; private set; }

    /// <summary>
    /// Подключение к базе данных PostgreSQL.
    /// <see langword="null"/>, если конфигурация не загружена или неполная.
    /// </summary>
    internal static Database? Database { get; private set; }

    /// <summary>
    /// Полный InstanceId (ULID, 26 символов). Write-once на весь срок жизни процесса.
    /// </summary>
    private static string? _instanceId;

    /// <summary>
    /// Полный InstanceId. Бросает <see cref="InvalidOperationException"/>, если ещё не инициализирован.
    /// </summary>
    internal static string InstanceId =>
        _instanceId ?? throw new InvalidOperationException("InstanceId ещё не инициализирован.");

    /// <summary>
    /// 12-символьный префикс InstanceId (нижний регистр) для имён AD-групп WebShelf-{id}-*.
    /// </summary>
    internal static string InstanceIdShort
    {
        get
        {
            string id = InstanceId;
            return id.Length >= 12 ? id[..12].ToLowerInvariant() : id.ToLowerInvariant();
        }
    }

    /// <summary>
    /// Устанавливает InstanceId один раз на весь срок жизни процесса.
    /// Повторный вызов вызывает <see cref="InvalidOperationException"/>.
    /// </summary>
    /// <param name="value">Полный ULID (26 символов).</param>
    internal static void SetInstanceId(string value)
    {
        const string method = nameof(SetInstanceId);

        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("InstanceId не может быть пустым.", nameof(value));

        if (_instanceId is not null)
            throw new InvalidOperationException("InstanceId уже установлен.");

        _instanceId = value.Trim();
        Log.Information(
            "InstanceId установлен в Data. Short={Short}. Class={Class}, Method={Method}",
            InstanceIdShort, ClassName, method);
    }

    /// <summary>
    /// Обязательные ключи домена в конфигурации. Учётные данные берутся из
    /// <c>sdomainuser</c>/<c>sdomainpass</c> либо из <c>domainuser</c>/<c>domainpass</c>.
    /// </summary>
    private static readonly string[] RequiredDomainKeys = ["domainname"];

    /// <summary>
    /// Читает файл Server.conf и инициализирует <see cref="Domain"/>,
    /// <see cref="Port"/> и <see cref="Scheme"/>.
    /// InstanceId должен быть установлен через <see cref="SetInstanceId"/> до вызова.
    /// </summary>
    /// <returns>
    /// <see langword="true"/>, если конфигурация прочитана успешно
    /// (файл существует, ключи найдены, объекты созданы, домен доступен);
    /// <see langword="false"/> — при любой ошибке.
    /// </returns>
    internal static bool ReadConfig()
    {
        const string method = nameof(ReadConfig);

        try
        {
            Log.Information(
                "Начало чтения конфигурации. Class={Class}, Method={Method}, ConfigFile={ConfigFile}",
                ClassName, method, ConfigFile);

            Domain = null;
            Database = null;
            Port = null;
            Scheme = null;

            if (_instanceId is null)
            {
                Log.Error(
                    "InstanceId не установлен до чтения конфигурации. Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
            }

            if (!File.Exists(ConfigFile))
            {
                Log.Error(
                    "Файл конфигурации не найден. Class={Class}, Method={Method}, ConfigFile={ConfigFile}",
                    ClassName, method, ConfigFile);
                return false;
            }

            Dictionary<string, string> config = ReadConfigFile(ConfigFile);

            if (config.Count == 0)
            {
                Log.Warning(
                    "Файл конфигурации пуст или не содержит валидных записей. Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
            }

            bool domainOk = TryInitDomain(config);
            bool databaseOk = TryInitDatabase(config);
            bool portOk = TryInitPort(config);
            bool schemeOk = TryInitScheme(config);

            if (!domainOk || !databaseOk || !portOk || !schemeOk)
            {
                Log.Error(
                    "Конфигурация загружена частично. DomainOk={DomainOk}, DatabaseOk={DatabaseOk}, PortOk={PortOk}, SchemeOk={SchemeOk}. Class={Class}, Method={Method}",
                    domainOk, databaseOk, portOk, schemeOk, ClassName, method);
                return false;
            }

            Log.Information(
                "Конфигурация успешно загружена. Domain={Domain}, Database={Database}, InstanceShort={InstanceShort}, Scheme={Scheme}, Port={Port}. Class={Class}, Method={Method}",
                Domain!.Name, Database!.DatabaseName, InstanceIdShort, Scheme, Port, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Исключение при чтении конфигурации. Class={Class}, Method={Method}, ConfigFile={ConfigFile}",
                ClassName, method, ConfigFile);

            Domain = null;
            Database = null;
            Port = null;
            Scheme = null;
            return false;
        }
    }

    /// <summary>
    /// Читает файл конфигурации в словарь ключ=значение.
    /// Строки-комментарии (начинающиеся с #) и пустые строки игнорируются.
    /// </summary>
    private static Dictionary<string, string> ReadConfigFile(string path)
    {
        const string method = nameof(ReadConfigFile);
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase);

        try
        {
            using StreamReader reader = new(path, Encoding.UTF8);

            string? line;
            int lineNumber = 0;

            while ((line = reader.ReadLine()) is not null)
            {
                lineNumber++;
                string trimmed = line.Trim();

                // Пустые строки и комментарии
                if (trimmed.Length == 0 || trimmed[0] == '#')
                    continue;

                int eqIndex = trimmed.IndexOf('=');
                if (eqIndex <= 0)
                {
                    Log.Debug(
                        "Пропущена некорректная строка конфигурации. Line={LineNumber}, Value={Value}. Class={Class}, Method={Method}",
                        lineNumber, trimmed, ClassName, method);
                    continue;
                }

                string key = trimmed[..eqIndex].Trim();
                string value = trimmed[(eqIndex + 1)..].Trim();

                if (key.Length == 0)
                {
                    Log.Debug(
                        "Пропущена строка с пустым ключом. Line={LineNumber}. Class={Class}, Method={Method}",
                        lineNumber, ClassName, method);
                    continue;
                }

                // При дубликатах — последнее значение побеждает
                config[key] = value;
            }

            Log.Debug(
                "Файл конфигурации прочитан. Keys={KeyCount}. Class={Class}, Method={Method}",
                config.Count, ClassName, method);

            return config;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка чтения файла конфигурации. Class={Class}, Method={Method}, Path={Path}",
                ClassName, method, path);
            throw;
        }
    }

    /// <summary>
    /// Инициализирует <see cref="Domain"/> из словаря конфигурации
    /// и проверяет доступность контроллера домена через сервисную учётную запись
    /// (без проверки группы Users).
    /// <para>
    /// Если заданы <c>sdomainuser</c> и <c>sdomainpass</c> — используются они
    /// (значения уже зашифрованы мастер-ключом).
    /// Если заданы <c>domainuser</c> и <c>domainpass</c> — значения шифруются мастер-ключом,
    /// записываются в <c>sdomainuser</c>/<c>sdomainpass</c>, открытые поля очищаются.
    /// </para>
    /// </summary>
    private static bool TryInitDomain(Dictionary<string, string> config)
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
                return false;
            }

            string domainName = config["domainname"];

            if (string.IsNullOrWhiteSpace(domainName))
            {
                Log.Error(
                    "Значение domainname пустое. Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
            }

            byte[]? masterKey = EncryptionService.EnsureMasterKey();
            if (masterKey is null)
            {
                Log.Error(
                    "Мастер-ключ недоступен при инициализации домена. Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
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
                    return false;
                }

                if (string.IsNullOrWhiteSpace(plainUser) || string.IsNullOrWhiteSpace(plainPass))
                {
                    Log.Error(
                        "После расшифровки sdomainuser/sdomainpass получены пустые значения. Class={Class}, Method={Method}",
                        ClassName, method);
                    return false;
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
                    return false;
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
                    return false;
                }

                if (!WriteSecureDomainCredentials(encryptedUser, encryptedPass))
                {
                    Log.Error(
                        "Не удалось записать sdomainuser/sdomainpass в конфигурацию. Class={Class}, Method={Method}",
                        ClassName, method);
                    return false;
                }

                Log.Information(
                    "Учётные данные домена зашифрованы и сохранены в sdomainuser/sdomainpass. Class={Class}, Method={Method}",
                    ClassName, method);
            }

            // В Domain передаём зашифрованные значения (принадлежность к WebShelf — через AD-группу)
            Domain = new Domain(domainName, encryptedUser, encryptedPass);

            Log.Information(
                "Домен инициализирован. Domain={Domain}, User={User}. Class={Class}, Method={Method}",
                Domain.Name, "SystemAccount", ClassName, method);

            // Проверка доступности AD: валидация сервисной учётки без проверки группы Users (открытый пароль)
            bool isAvailable = Domain.ValidateAdCredentials(plainUser, plainPass, checkUsersGroup: false);
            if (!isAvailable)
            {
                Log.Error(
                    "Домен недоступен или сервисная учётная запись невалидна. Domain={Domain}, User={User}. Class={Class}, Method={Method}",
                    Domain.Name, "SystemAccount", ClassName, method);
                Domain = null;
                return false;
            }

            Log.Information(
                "Доступность домена подтверждена. Domain={Domain}. Class={Class}, Method={Method}",
                Domain.Name, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка инициализации домена. Class={Class}, Method={Method}",
                ClassName, method);
            Domain = null;
            return false;
        }
    }

    /// <summary>
    /// Записывает зашифрованные <c>sdomainuser</c> и <c>sdomainpass</c> в Server.conf,
    /// очищает значения <c>domainuser</c> и <c>domainpass</c>.
    /// Сохраняет комментарии и порядок остальных строк.
    /// </summary>
    /// <param name="encryptedUser">Зашифрованное имя сервисной учётки (Base64).</param>
    /// <param name="encryptedPass">Зашифрованный пароль сервисной учётки (Base64).</param>
    /// <returns><see langword="true"/> при успешной записи; иначе <see langword="false"/>.</returns>
    private static bool WriteSecureDomainCredentials(string encryptedUser, string encryptedPass)
    {
        const string method = nameof(WriteSecureDomainCredentials);

        try
        {
            if (!File.Exists(ConfigFile))
            {
                Log.Error(
                    "Файл конфигурации не найден при записи sdomain*. Class={Class}, Method={Method}, Path={Path}",
                    ClassName, method, ConfigFile);
                return false;
            }

            string[] lines = File.ReadAllLines(ConfigFile, Encoding.UTF8);
            List<string> result = new(lines.Length + 4);

            bool hasSUser = false;
            bool hasSPass = false;
            bool hasDomainUser = false;
            bool hasDomainPass = false;

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

                if (key.Equals("sdomainuser", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add($"sdomainuser={encryptedUser}");
                    hasSUser = true;
                }
                else if (key.Equals("sdomainpass", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add($"sdomainpass={encryptedPass}");
                    hasSPass = true;
                }
                else if (key.Equals("domainuser", StringComparison.OrdinalIgnoreCase))
                {
                    // Открытый логин очищаем после переноса в sdomainuser
                    result.Add("domainuser=");
                    hasDomainUser = true;
                }
                else if (key.Equals("domainpass", StringComparison.OrdinalIgnoreCase))
                {
                    // Открытый пароль очищаем после переноса в sdomainpass
                    result.Add("domainpass=");
                    hasDomainPass = true;
                }
                else
                {
                    result.Add(line);
                }
            }

            if (!hasSUser)
                result.Add($"sdomainuser={encryptedUser}");
            if (!hasSPass)
                result.Add($"sdomainpass={encryptedPass}");
            if (!hasDomainUser)
                result.Add("domainuser=");
            if (!hasDomainPass)
                result.Add("domainpass=");

            File.WriteAllLines(ConfigFile, result, Encoding.UTF8);

            Log.Information(
                "Зашифрованные учётные данные домена записаны в конфигурацию. Class={Class}, Method={Method}",
                ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка записи sdomainuser/sdomainpass. Class={Class}, Method={Method}, Path={Path}",
                ClassName, method, ConfigFile);
            return false;
        }
    }



    /// <summary>
    /// Инициализирует <see cref="Database"/> из словаря конфигурации
    /// и проверяет доступность PostgreSQL через сервисную учётную запись.
    /// <para>
    /// Если заданы <c>sdbuser</c> и <c>sdbpass</c> — используются они
    /// (значения уже зашифрованы мастер-ключом).
    /// Если заданы <c>dbuser</c> и <c>dbpass</c> — значения шифруются мастер-ключом,
    /// записываются в <c>sdbuser</c>/<c>sdbpass</c>, открытые поля очищаются.
    /// </para>
    /// </summary>
    private static bool TryInitDatabase(Dictionary<string, string> config)
    {
        const string method = nameof(TryInitDatabase);

        try
        {
            if (!config.TryGetValue("dbhost", out string? host) || string.IsNullOrWhiteSpace(host))
            {
                Log.Error("Отсутствует или пустой ключ dbhost. Class={Class}, Method={Method}", ClassName, method);
                return false;
            }

            int port = 5432;
            if (config.TryGetValue("dbport", out string? portStr) && !string.IsNullOrWhiteSpace(portStr))
            {
                if (!int.TryParse(portStr.Trim(), out port) || port < 1 || port > 65535)
                {
                    Log.Error(
                        "Некорректное значение dbport={PortValue}. Class={Class}, Method={Method}",
                        portStr, ClassName, method);
                    return false;
                }
            }

            if (!config.TryGetValue("dbname", out string? dbName) || string.IsNullOrWhiteSpace(dbName))
            {
                Log.Error("Отсутствует или пустой ключ dbname. Class={Class}, Method={Method}", ClassName, method);
                return false;
            }

            // dbsslmode: Disable | Prefer | Require | VerifyCA | VerifyFull (по умолчанию Require)
            SslMode sslMode = SslMode.Require;
            if (config.TryGetValue("dbsslmode", out string? sslModeStr) && !string.IsNullOrWhiteSpace(sslModeStr))
            {
                if (!Enum.TryParse(sslModeStr.Trim(), ignoreCase: true, out sslMode) ||
                    !Enum.IsDefined(typeof(SslMode), sslMode))
                {
                    Log.Error(
                        "Некорректное значение dbsslmode={SslModeValue}. Допустимо: Disable, Prefer, Require, VerifyCA, VerifyFull. Class={Class}, Method={Method}",
                        sslModeStr, ClassName, method);
                    return false;
                }
            }

            Log.Information(
                "Режим SSL для БД: {SslMode}. Class={Class}, Method={Method}",
                sslMode, ClassName, method);

            byte[]? masterKey = EncryptionService.EnsureMasterKey();
            if (masterKey is null)
            {
                Log.Error(
                    "Мастер-ключ недоступен для инициализации БД. Class={Class}, Method={Method}",
                    ClassName, method);
                return false;
            }

            config.TryGetValue("sdbuser", out string? sUser);
            config.TryGetValue("sdbpass", out string? sPass);

            string encryptedUser;
            string encryptedPass;
            string plainUser;
            string plainPass;

            bool hasSecure =
                !string.IsNullOrWhiteSpace(sUser) &&
                !string.IsNullOrWhiteSpace(sPass);

            if (hasSecure)
            {
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
                        "Не удалось расшифровать sdbuser/sdbpass. Class={Class}, Method={Method}",
                        ClassName, method);
                    return false;
                }

                if (string.IsNullOrWhiteSpace(plainUser) || string.IsNullOrWhiteSpace(plainPass))
                {
                    Log.Error(
                        "После расшифровки sdbuser/sdbpass получены пустые значения. Class={Class}, Method={Method}",
                        ClassName, method);
                    return false;
                }

                Log.Information(
                    "Учётные данные БД загружены из sdbuser/sdbpass. Class={Class}, Method={Method}",
                    ClassName, method);
            }
            else
            {
                if (!config.TryGetValue("dbuser", out string? dbUser) ||
                    !config.TryGetValue("dbpass", out string? dbPass) ||
                    string.IsNullOrWhiteSpace(dbUser) ||
                    string.IsNullOrWhiteSpace(dbPass))
                {
                    Log.Error(
                        "Отсутствуют dbuser/dbpass и sdbuser/sdbpass. Class={Class}, Method={Method}",
                        ClassName, method);
                    return false;
                }

                plainUser = dbUser.Trim();
                plainPass = dbPass.Trim();

                try
                {
                    encryptedUser = EncryptionService.Encrypt(plainUser, masterKey);
                    encryptedPass = EncryptionService.Encrypt(plainPass, masterKey);
                }
                catch (Exception ex)
                {
                    Log.Error(ex,
                        "Не удалось зашифровать dbuser/dbpass. Class={Class}, Method={Method}",
                        ClassName, method);
                    return false;
                }

                if (!WriteSecureDbCredentials(encryptedUser, encryptedPass))
                {
                    Log.Error(
                        "Не удалось записать sdbuser/sdbpass в конфигурацию. Class={Class}, Method={Method}",
                        ClassName, method);
                    return false;
                }

                Log.Information(
                    "Учётные данные БД зашифрованы и сохранены в sdbuser/sdbpass. Class={Class}, Method={Method}",
                    ClassName, method);
            }

            Database = new Database(host.Trim(), port, dbName.Trim(), sslMode, encryptedUser, encryptedPass);

            Log.Information(
                "БД инициализирована. Host={Host}, Port={Port}, Database={Database}, SslMode={SslMode}, User={User}. Class={Class}, Method={Method}",
                Database.Host, Database.Port, Database.DatabaseName, Database.SslMode, "SystemAccount", ClassName, method);

            // Синхронная обёртка над async-проверкой: на этапе старта допустимо
            bool isAvailable = Database.ValidateConnectionAsync().GetAwaiter().GetResult();
            if (!isAvailable)
            {
                Log.Error(
                    "БД недоступна или сервисная учётная запись невалидна. Host={Host}, Database={Database}, User={User}. Class={Class}, Method={Method}",
                    Database.Host, Database.DatabaseName, "SystemAccount", ClassName, method);
                Database.Dispose();
                Database = null;
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка инициализации БД. Class={Class}, Method={Method}",
                ClassName, method);
            Database?.Dispose();
            Database = null;
            return false;
        }
    }

    /// <summary>
    /// Записывает зашифрованные <c>sdbuser</c> и <c>sdbpass</c> в Server.conf,
    /// очищает значения <c>dbuser</c> и <c>dbpass</c>.
    /// Сохраняет комментарии и порядок остальных строк.
    /// </summary>
    /// <param name="encryptedUser">Зашифрованное имя сервисной учётки БД (Base64).</param>
    /// <param name="encryptedPass">Зашифрованный пароль сервисной учётки БД (Base64).</param>
    /// <returns><see langword="true"/> при успешной записи; иначе <see langword="false"/>.</returns>
    private static bool WriteSecureDbCredentials(string encryptedUser, string encryptedPass)
    {
        const string method = nameof(WriteSecureDbCredentials);

        try
        {
            if (!File.Exists(ConfigFile))
            {
                Log.Error(
                    "Файл конфигурации не найден при записи sdb*. Class={Class}, Method={Method}, Path={Path}",
                    ClassName, method, ConfigFile);
                return false;
            }

            string[] lines = File.ReadAllLines(ConfigFile, Encoding.UTF8);
            List<string> result = new(lines.Length + 4);

            bool hasSUser = false;
            bool hasSPass = false;
            bool hasDbUser = false;
            bool hasDbPass = false;

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

                if (key.Equals("sdbuser", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add($"sdbuser={encryptedUser}");
                    hasSUser = true;
                }
                else if (key.Equals("sdbpass", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add($"sdbpass={encryptedPass}");
                    hasSPass = true;
                }
                else if (key.Equals("dbuser", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add("dbuser=");
                    hasDbUser = true;
                }
                else if (key.Equals("dbpass", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add("dbpass=");
                    hasDbPass = true;
                }
                else
                {
                    result.Add(line);
                }
            }

            if (!hasSUser)
                result.Add($"sdbuser={encryptedUser}");
            if (!hasSPass)
                result.Add($"sdbpass={encryptedPass}");
            if (!hasDbUser)
                result.Add("dbuser=");
            if (!hasDbPass)
                result.Add("dbpass=");

            File.WriteAllLines(ConfigFile, result, Encoding.UTF8);

            Log.Information(
                "Зашифрованные учётные данные БД записаны в конфигурацию. Class={Class}, Method={Method}",
                ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка записи sdbuser/sdbpass. Class={Class}, Method={Method}, Path={Path}",
                ClassName, method, ConfigFile);
            return false;
        }
    }

    /// <summary>
    /// Читает и проверяет порт из конфигурации.
    /// </summary>
    private static bool TryInitPort(Dictionary<string, string> config)
    {
        const string method = nameof(TryInitPort);

        try
        {
            if (!config.TryGetValue("port", out string? portStr) || string.IsNullOrWhiteSpace(portStr))
            {
                Log.Error("Отсутствует или пустой ключ port. Class={Class}, Method={Method}", ClassName, method);
                return false;
            }

            if (!int.TryParse(portStr.Trim(), out int port) || port < 1 || port > 65535)
            {
                Log.Error("Некорректное значение port={PortValue}. Class={Class}, Method={Method}", portStr, ClassName, method);
                return false;
            }

            Port = port;

            Log.Information("Порт сервера установлен. Port={Port}. Class={Class}, Method={Method}", Port, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Ошибка инициализации порта. Class={Class}, Method={Method}", ClassName, method);
            Port = null;
            return false;
        }
    }

    /// <summary>
    /// Читает и проверяет схему (http/https) из конфигурации.
    /// </summary>
    private static bool TryInitScheme(Dictionary<string, string> config)
    {
        const string method = nameof(TryInitScheme);

        try
        {
            if (!config.TryGetValue("scheme", out string? schemeStr) || string.IsNullOrWhiteSpace(schemeStr))
            {
                Log.Error("Отсутствует или пустой ключ scheme. Class={Class}, Method={Method}", ClassName, method);
                return false;
            }

            string scheme = schemeStr.Trim().ToLowerInvariant();

            if (scheme is not ("http" or "https"))
            {
                Log.Error(
                    "Некорректное значение scheme={SchemeValue}. Допустимо: http, https. Class={Class}, Method={Method}",
                    schemeStr, ClassName, method);
                return false;
            }

            Scheme = scheme;

            Log.Information("Схема сервера установлена. Scheme={Scheme}. Class={Class}, Method={Method}", Scheme, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Ошибка инициализации схемы. Class={Class}, Method={Method}", ClassName, method);
            Scheme = null;
            return false;
        }
    }
}
