using Npgsql;
using WebShelf.Classes.Crypto;
using WebShelf.Classes.DB;

namespace WebShelf.Classes.Service.Configuration.Sections;

/// <summary>
/// Инициализатор секции базы данных PostgreSQL: читает параметры подключения
/// и сервисной учётной записи из словаря конфигурации, выполняет миграцию
/// открытых учётных данных в защищённые и проверяет доступность сервера.
/// </summary>
/// <remarks>
/// Класс выделен из <c>Data</c> механическим переносом (шаг 6 дорожной
/// карты декомпозиции, точка решения о секциях: <c>Data</c> после выноса
/// записи остаётся больше ~550 строк). Правки при переносе — константа
/// <c>Class=</c> в логах перенесённого кода (принцип 6 дорожной карты)
/// и возврат результата вместо мутации состояния <c>Data</c>: метод
/// возвращает готовый экземпляр <see cref="Database"/> либо
/// <see langword="null"/>, присваивание свойству выполняет оркестратор
/// <see cref="Data.ReadConfigAsync"/>. Шаг 8 дорожной карты (улучшение У3):
/// криптография поступает параметрами как инстансные зависимости
/// <see cref="KeyStore"/> и <see cref="CryptoEngine"/> вместо статических
/// вызовов фасада — поведение не менялось.
/// </remarks>
internal static class DatabaseSection
{
    private const string ClassName = "WebShelf.Classes.Service.Configuration.Sections.DatabaseSection";

    /// <summary>
    /// Асинхронно инициализирует подключение к PostgreSQL из словаря
    /// конфигурации и проверяет его доступность через сервисную учётную запись.
    /// Расшифровка и валидация учётных данных выполняются однократно
    /// в конструкторе <see cref="Database"/>.
    /// <para>
    /// Если заданы <c>sdbuser</c> и <c>sdbpass</c> — используются они
    /// (значения уже зашифрованы мастер-ключом).
    /// Если заданы <c>dbuser</c> и <c>dbpass</c> — значения шифруются мастер-ключом,
    /// записываются в <c>sdbuser</c>/<c>sdbpass</c>, открытые поля очищаются.
    /// </para>
    /// </summary>
    /// <param name="config">Словарь конфигурации (результат разбора Server.conf).</param>
    /// <param name="credentialsWriter">Писатель защищённых учётных данных в Server.conf.</param>
    /// <param name="keyStore">Хранилище ключей — источник мастер-ключа
    /// (в Production — singleton из DI; улучшение У3 дорожной карты декомпозиции).</param>
    /// <param name="cryptoEngine">Криптографический движок — шифрование
    /// учётных данных (в Production — singleton из DI).</param>
    /// <returns>
    /// Готовый экземпляр <see cref="Database"/> при успешной инициализации;
    /// <see langword="null"/> — при любой ошибке (отсутствие ключей,
    /// недоступность мастер-ключа, недоступность сервера). Экземпляр,
    /// не прошедший проверку доступности, освобождается внутри метода.
    /// </returns>
    internal static async Task<Database?> TryInitDatabaseAsync(
        Dictionary<string, string> config,
        SecureCredentialsWriter credentialsWriter,
        KeyStore keyStore,
        CryptoEngine cryptoEngine)
    {
        const string method = nameof(TryInitDatabaseAsync);

        ArgumentNullException.ThrowIfNull(keyStore);
        ArgumentNullException.ThrowIfNull(cryptoEngine);

        Database? database = null;

        try
        {
            if (!config.TryGetValue("dbhost", out string? host) || string.IsNullOrWhiteSpace(host))
            {
                Log.Error("Отсутствует или пустой ключ dbhost. Class={Class}, Method={Method}", ClassName, method);
                return null;
            }

            int port = 5432;
            if (config.TryGetValue("dbport", out string? portStr) && !string.IsNullOrWhiteSpace(portStr))
            {
                if (!int.TryParse(portStr.Trim(), out port) || port < 1 || port > 65535)
                {
                    Log.Error(
                        "Некорректное значение dbport={PortValue}. Class={Class}, Method={Method}",
                        portStr, ClassName, method);
                    return null;
                }
            }

            if (!config.TryGetValue("dbname", out string? dbName) || string.IsNullOrWhiteSpace(dbName))
            {
                Log.Error("Отсутствует или пустой ключ dbname. Class={Class}, Method={Method}", ClassName, method);
                return null;
            }

            // dbsslmode: Disable | Allow | Prefer | Require | VerifyCA | VerifyFull (по умолчанию Require)
            SslMode sslMode = SslMode.Require;
            if (config.TryGetValue("dbsslmode", out string? sslModeStr) && !string.IsNullOrWhiteSpace(sslModeStr))
            {
                if (!Enum.TryParse(sslModeStr.Trim(), ignoreCase: true, out sslMode) ||
                    !Enum.IsDefined(sslMode))
                {
                    Log.Error(
                        "Некорректное значение dbsslmode={SslModeValue}. Допустимо: Disable, Allow, Prefer, Require, VerifyCA, VerifyFull. Class={Class}, Method={Method}",
                        sslModeStr, ClassName, method);
                    return null;
                }
            }

            Log.Information(
                "Режим SSL для БД: {SslMode}. Class={Class}, Method={Method}",
                sslMode, ClassName, method);

            // Отключённый SSL передаёт пароль сервисной записи БД по сети в открытом виде.
            // Допустимо только внутри изолированного сегмента сети — предупреждение
            // симметрично предупреждению о схеме http в Program.cs
            if (sslMode == SslMode.Disable)
            {
                Log.Warning(
                    "SSL отключён (dbsslmode=Disable): учётные данные БД передаются по сети без шифрования. Рекомендуется Require и выше. Class={Class}, Method={Method}",
                    ClassName, method);
            }

            byte[]? masterKey = keyStore.EnsureMasterKey();
            if (masterKey is null)
            {
                Log.Error(
                    "Мастер-ключ недоступен для инициализации БД. Class={Class}, Method={Method}",
                    ClassName, method);
                return null;
            }

            string? secureUser = config.TryGetValue("sdbuser", out string? sUser) && !string.IsNullOrWhiteSpace(sUser)
                ? sUser
                : null;
            string? securePass = config.TryGetValue("sdbpass", out string? sPass) && !string.IsNullOrWhiteSpace(sPass)
                ? sPass
                : null;

            string encryptedUser;
            string encryptedPass;

            if (secureUser is not null && securePass is not null)
            {
                // Расшифровка и валидация учётных данных выполняется однократно
                // в конструкторе Database — здесь повторно не расшифровываем
                encryptedUser = secureUser.Trim();
                encryptedPass = securePass.Trim();

                Log.Information(
                    "Учётные данные БД загружены из sdbuser/sdbpass. Class={Class}, Method={Method}",
                    ClassName, method);

                // Остаточные открытые dbuser/dbpass подлежат очистке: секреты
                // не должны оставаться в конфигурации в незашифрованном виде
                config.TryGetValue("dbuser", out string? leftoverUser);
                config.TryGetValue("dbpass", out string? leftoverPass);

                bool hasPlainLeftovers =
                    !string.IsNullOrWhiteSpace(leftoverUser) ||
                    !string.IsNullOrWhiteSpace(leftoverPass);

                if (hasPlainLeftovers)
                {
                    if (credentialsWriter.WriteSecureDbCredentials(encryptedUser, encryptedPass))
                    {
                        Log.Information(
                            "Остаточные открытые dbuser/dbpass очищены в конфигурации. Class={Class}, Method={Method}",
                            ClassName, method);
                    }
                    else
                    {
                        Log.Warning(
                            "Не удалось очистить остаточные открытые dbuser/dbpass. Class={Class}, Method={Method}",
                            ClassName, method);
                    }
                }
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
                    return null;
                }

                string plainUser = dbUser.Trim();
                string plainPass = dbPass.Trim();

                try
                {
                    encryptedUser = cryptoEngine.Encrypt(plainUser, masterKey, CryptoContexts.DatabaseUser);
                    encryptedPass = cryptoEngine.Encrypt(plainPass, masterKey, CryptoContexts.DatabasePassword);
                }
                catch (Exception ex)
                {
                    Log.Error(ex,
                        "Не удалось зашифровать dbuser/dbpass. Class={Class}, Method={Method}",
                        ClassName, method);
                    return null;
                }

                if (!credentialsWriter.WriteSecureDbCredentials(encryptedUser, encryptedPass))
                {
                    Log.Error(
                        "Не удалось записать sdbuser/sdbpass в конфигурацию. Class={Class}, Method={Method}",
                        ClassName, method);
                    return null;
                }

                Log.Information(
                    "Учётные данные БД зашифрованы и сохранены в sdbuser/sdbpass. Class={Class}, Method={Method}",
                    ClassName, method);
            }

            database = new Database(host.Trim(), port, dbName.Trim(), sslMode, encryptedUser, encryptedPass, keyStore, cryptoEngine);

            Log.Information(
                "БД инициализирована. Host={Host}, Port={Port}, Database={Database}, SslMode={SslMode}, User={User}. Class={Class}, Method={Method}",
                database.Host, database.Port, database.DatabaseName, database.SslMode, "SystemAccount", ClassName, method);

            // Проверка доступности выполняется асинхронно: TryInitDatabaseAsync
            // вызывается из Program.Main через await, без sync-over-async
            bool isAvailable = await database.ValidateConnectionAsync().ConfigureAwait(false);
            if (!isAvailable)
            {
                Log.Error(
                    "БД недоступна или сервисная учётная запись невалидна. Host={Host}, Database={Database}, User={User}. Class={Class}, Method={Method}",
                    database.Host, database.DatabaseName, "SystemAccount", ClassName, method);
                database.Dispose();
                return null;
            }

            return database;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка инициализации БД. Class={Class}, Method={Method}",
                ClassName, method);
            database?.Dispose();
            return null;
        }
    }
}
