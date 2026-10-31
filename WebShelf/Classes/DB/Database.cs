using Npgsql;
using Serilog;
using WebShelf.Classes.Service;

namespace WebShelf.Classes.DB;

/// <summary>
/// Представляет подключение к базе данных PostgreSQL приложения WebShelf.
/// Хранит параметры соединения, зашифрованные учётные данные и единый
/// <see cref="NpgsqlDataSource"/> на весь срок жизни процесса.
/// </summary>
/// <remarks>
/// Учётные данные сервисной записи БД хранятся только в зашифрованном виде
/// (мастер-ключ). Перед использованием расшифровываются. Пароли и реальные
/// имена учётных записей в логи не попадают.
/// </remarks>
internal sealed class Database : IAsyncDisposable, IDisposable
{
    private const string ClassName = "WebShelf.Classes.DB.Database";

    /// <summary>
    /// Хост PostgreSQL (имя или IP).
    /// </summary>
    internal string Host { get; }

    /// <summary>
    /// Порт PostgreSQL (1–65535). По умолчанию 5432.
    /// </summary>
    internal int Port { get; }

    /// <summary>
    /// Имя базы данных.
    /// </summary>
    internal string DatabaseName { get; }

    /// <summary>
    /// Режим SSL/TLS при подключении к PostgreSQL.
    /// </summary>
    internal SslMode SslMode { get; }

    /// <summary>
    /// Зашифрованное имя сервисной учётной записи БД (мастер-ключ).
    /// </summary>
    private readonly string _encryptedUser;

    /// <summary>
    /// Зашифрованный пароль сервисной учётной записи БД (мастер-ключ).
    /// </summary>
    private readonly string _encryptedPassword;

    /// <summary>
    /// Единый источник соединений на весь срок жизни процесса.
    /// </summary>
    private readonly NpgsqlDataSource _dataSource;

    private bool _disposed;

    /// <summary>
    /// Создаёт экземпляр <see cref="Database"/>.
    /// Параметры <paramref name="encryptedUser"/> и <paramref name="encryptedPassword"/>
    /// должны быть уже зашифрованы мастер-ключом (<see cref="EncryptionService"/>).
    /// </summary>
    /// <param name="host">Хост PostgreSQL.</param>
    /// <param name="port">Порт PostgreSQL.</param>
    /// <param name="databaseName">Имя базы данных.</param>
    /// <param name="sslMode">Режим SSL/TLS.</param>
    /// <param name="encryptedUser">Зашифрованное имя сервисной учётной записи (Base64).</param>
    /// <param name="encryptedPassword">Зашифрованный пароль сервисной учётной записи (Base64).</param>
    /// <exception cref="ArgumentException">
    /// Возникает, если host, databaseName пустые, порт вне диапазона 1–65535
    /// либо после расшифровки логин/пароль пустые.
    /// </exception>
    internal Database(
        string host,
        int port,
        string databaseName,
        SslMode sslMode,
        string encryptedUser,
        string encryptedPassword)
    {
        const string method = nameof(Database);

        if (string.IsNullOrWhiteSpace(host))
            throw new ArgumentException("Хост базы данных не может быть пустым.", nameof(host));

        if (port < 1 || port > 65535)
            throw new ArgumentException("Порт базы данных должен быть в диапазоне 1–65535.", nameof(port));

        if (string.IsNullOrWhiteSpace(databaseName))
            throw new ArgumentException("Имя базы данных не может быть пустым.", nameof(databaseName));

        if (string.IsNullOrWhiteSpace(encryptedUser))
            throw new ArgumentException("Зашифрованное имя учётной записи БД не может быть пустым.", nameof(encryptedUser));

        if (string.IsNullOrWhiteSpace(encryptedPassword))
            throw new ArgumentException("Зашифрованный пароль учётной записи БД не может быть пустым.", nameof(encryptedPassword));

        Host = host.Trim();
        Port = port;
        DatabaseName = databaseName.Trim();
        SslMode = sslMode;
        _encryptedUser = encryptedUser.Trim();
        _encryptedPassword = encryptedPassword.Trim();

        string plainUser = DecryptUser();
        string plainPass = DecryptPassword();

        if (string.IsNullOrWhiteSpace(plainUser) || string.IsNullOrWhiteSpace(plainPass))
        {
            throw new ArgumentException(
                "После расшифровки учётные данные БД пустые.",
                nameof(encryptedUser));
        }

        string connectionString = BuildConnectionString(Host, Port, DatabaseName, SslMode, plainUser, plainPass);

        try
        {
            _dataSource = NpgsqlDataSource.Create(connectionString);
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Не удалось создать NpgsqlDataSource. Host={Host}, Port={Port}, Database={Database}, SslMode={SslMode}. Class={Class}, Method={Method}",
                Host, Port, DatabaseName, SslMode, ClassName, method);
            throw;
        }

        Log.Information(
            "Database инициализирован. Host={Host}, Port={Port}, Database={Database}, SslMode={SslMode}, User={User}. Class={Class}, Method={Method}",
            Host, Port, DatabaseName, SslMode, "SystemAccount", ClassName, method);
    }

    /// <summary>
    /// Открывает соединение из пула <see cref="NpgsqlDataSource"/>.
    /// Вызывающий код обязан освободить соединение через <c>await using</c>.
    /// </summary>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Открытое <see cref="NpgsqlConnection"/>.</returns>
    internal async Task<NpgsqlConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
    {
        const string method = nameof(OpenConnectionAsync);
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            NpgsqlConnection connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Ошибка открытия соединения с БД. Host={Host}, Port={Port}, Database={Database}, SslMode={SslMode}. Class={Class}, Method={Method}",
                Host, Port, DatabaseName, SslMode, ClassName, method);
            throw;
        }
    }

    /// <summary>
    /// Проверяет доступность базы данных простым запросом <c>SELECT 1</c>.
    /// </summary>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>
    /// <see langword="true"/>, если соединение успешно и запрос выполнен;
    /// иначе <see langword="false"/>.
    /// </returns>
    internal async Task<bool> ValidateConnectionAsync(CancellationToken cancellationToken = default)
    {
        const string method = nameof(ValidateConnectionAsync);
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            await using NpgsqlConnection connection = await OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using NpgsqlCommand command = connection.CreateCommand();
            command.CommandText = "SELECT 1";
            object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);

            bool ok = (result is int i && i == 1) || (result is long l && l == 1);

            if (ok)
            {
                Log.Information(
                    "Доступность БД подтверждена. Host={Host}, Port={Port}, Database={Database}, SslMode={SslMode}. Class={Class}, Method={Method}",
                    Host, Port, DatabaseName, SslMode, ClassName, method);
            }
            else
            {
                Log.Error(
                    "Проверка БД вернула неожиданный результат. Host={Host}, Port={Port}, Database={Database}, SslMode={SslMode}. Class={Class}, Method={Method}",
                    Host, Port, DatabaseName, SslMode, ClassName, method);
            }

            return ok;
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "БД недоступна или учётные данные невалидны. Host={Host}, Port={Port}, Database={Database}, SslMode={SslMode}, User={User}. Class={Class}, Method={Method}",
                Host, Port, DatabaseName, SslMode, "SystemAccount", ClassName, method);
            return false;
        }
    }

    /// <summary>
    /// Формирует строку подключения Npgsql.
    /// </summary>
    private static string BuildConnectionString(
        string host,
        int port,
        string databaseName,
        SslMode sslMode,
        string user,
        string password)
    {
        NpgsqlConnectionStringBuilder builder = new()
        {
            Host = host,
            Port = port,
            Database = databaseName,
            Username = user,
            Password = password,
            SslMode = sslMode,
            Pooling = true,
            // Таймаут подключения по умолчанию 15 с — достаточно для локальной/корпоративной сети
            Timeout = 15
        };

        return builder.ConnectionString;
    }

    /// <summary>
    /// Расшифровывает имя сервисной учётной записи БД.
    /// </summary>
    private string DecryptUser()
    {
        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        if (masterKey is null)
            throw new InvalidOperationException("Мастер-ключ недоступен для расшифровки учётных данных БД.");

        return EncryptionService.Decrypt(_encryptedUser, masterKey);
    }

    /// <summary>
    /// Расшифровывает пароль сервисной учётной записи БД.
    /// </summary>
    private string DecryptPassword()
    {
        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        if (masterKey is null)
            throw new InvalidOperationException("Мастер-ключ недоступен для расшифровки учётных данных БД.");

        return EncryptionService.Decrypt(_encryptedPassword, masterKey);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
            return;

        _dataSource.Dispose();
        _disposed = true;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        await _dataSource.DisposeAsync().ConfigureAwait(false);
        _disposed = true;
    }
}
