using Npgsql;
using System.Runtime.CompilerServices;
using WebShelf.Classes.Crypto;
using WebShelf.Classes.DB;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Инфраструктура интеграционных тестов сервисной инфраструктуры БД: создание
/// изолированной тестовой базы данных и экземпляра <see cref="Database"/> с
/// подменой хранилища ключей (<see cref="CryptoTestFakes.FakeKeyStore"/>).
/// Тесты выполняются только при заданной переменной окружения
/// <see cref="ConnectionStringEnvironmentVariable"/> (строка подключения к серверу
/// PostgreSQL 14+ с правами создания баз данных); иначе пропускаются.
/// </summary>
internal static class DbTestHelpers
{
    /// <summary>Имя переменной окружения со строкой подключения к тестовому серверу PostgreSQL.</summary>
    internal const string ConnectionStringEnvironmentVariable = "WEBSHELF_TEST_PG";

    /// <summary>Признак доступности настройки тестового сервера PostgreSQL.</summary>
    internal static bool IsPostgresConfigured =>
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(ConnectionStringEnvironmentVariable));

    /// <summary>
    /// Разбирает строку подключения администратора из переменной окружения.
    /// </summary>
    internal static NpgsqlConnectionStringBuilder ParseAdminConnectionString()
    {
        string? value = Environment.GetEnvironmentVariable(ConnectionStringEnvironmentVariable);
        NpgsqlConnectionStringBuilder builder = new(value);
        builder.Database = string.IsNullOrWhiteSpace(builder.Database) ? "postgres" : builder.Database;
        return builder;
    }

    /// <summary>
    /// Создаёт изолированную тестовую базу данных и возвращает аренду с данными
    /// для подключения; при освобождении база удаляется (WITH FORCE).
    /// </summary>
    internal static async Task<TestDatabaseLease> CreateTestDatabaseAsync()
    {
        NpgsqlConnectionStringBuilder admin = ParseAdminConnectionString();
        string databaseName = $"webshelf_it_{Guid.NewGuid():N}";

        await using NpgsqlConnection connection = new(admin.ConnectionString);
        await connection.OpenAsync();

        await using NpgsqlCommand command = connection.CreateCommand();
        // Имя сгенерировано приложением и экранировано — значения извне не подставляются
        command.CommandText = $"CREATE DATABASE {SchemaTextNormalizer.QuoteIdentifier(databaseName)}";
        await command.ExecuteNonQueryAsync();

        return new TestDatabaseLease(admin.ConnectionString, databaseName);
    }

    /// <summary>
    /// Создаёт экземпляр <see cref="Database"/> для тестового подключения:
    /// учётные данные шифруются синтетическим мастер-ключом (реестр не затрагивается).
    /// </summary>
    internal static Database CreateDatabase(
        string host,
        int port,
        string databaseName,
        string username,
        string password,
        SslMode sslMode)
    {
        KeyStore keyStore = new CryptoTestFakes.FakeKeyStore();
        CryptoEngine cryptoEngine = new();
        byte[] masterKey = keyStore.EnsureMasterKey()!;

        string encryptedUser = cryptoEngine.Encrypt(username, masterKey, CryptoContexts.DatabaseUser);
        string encryptedPassword = cryptoEngine.Encrypt(password, masterKey, CryptoContexts.DatabasePassword);

        return new Database(host, port, databaseName, sslMode, encryptedUser, encryptedPassword, keyStore, cryptoEngine);
    }

    /// <summary>
    /// Аренда тестовой базы данных: освобождение удаляет базу принудительно.
    /// </summary>
    internal sealed class TestDatabaseLease(string adminConnectionString, string databaseName) : IAsyncDisposable
    {
        /// <summary>Имя тестовой базы данных.</summary>
        internal string DatabaseName => databaseName;

        /// <summary>Строка подключения администратора (сервер).</summary>
        internal string AdminConnectionString => adminConnectionString;

        /// <inheritdoc />
        public async ValueTask DisposeAsync()
        {
            try
            {
                await using NpgsqlConnection connection = new(adminConnectionString);
                await connection.OpenAsync();

                await using NpgsqlCommand command = connection.CreateCommand();
                command.CommandText = $"DROP DATABASE {SchemaTextNormalizer.QuoteIdentifier(databaseName)} WITH (FORCE)";
                await command.ExecuteNonQueryAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Не удалось удалить тестовую базу {databaseName}: {ex.Message}");
            }
        }
    }
}

/// <summary>
/// Факт интеграционного теста с реальным PostgreSQL: тест выполняется только
/// при заданной переменной окружения <c>WEBSHELF_TEST_PG</c>, иначе пропускается.
/// Условие задаётся атрибутом; конструктор пробрасывает сведения об источнике
/// (требование xUnit3003 для наследников <see cref="FactAttribute"/>).
/// </summary>
internal sealed class PostgresFactAttribute : FactAttribute
{
    /// <summary>Инициализирует атрибут и проверяет доступность тестового сервера.</summary>
    /// <param name="sourceFilePath">Путь к файлу источника (заполняется компилятором).</param>
    /// <param name="sourceLineNumber">Номер строки источника (заполняется компилятором).</param>
    public PostgresFactAttribute(
        [CallerFilePath] string? sourceFilePath = null,
        [CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath ?? string.Empty, sourceLineNumber)
    {
        if (!DbTestHelpers.IsPostgresConfigured)
        {
            Skip = $"Интеграционный тест пропущен: не задана переменная окружения {DbTestHelpers.ConnectionStringEnvironmentVariable} (строка подключения к PostgreSQL 14+ с правами создания баз данных)";
        }
    }
}

/// <summary>
/// Восстановление дампа WebShelf на соединение PostgreSQL: обычные операторы
/// выполняются пакетами, блоки <c>COPY … FROM STDIN</c> — через текстовый импорт.
/// Воспроизводит поведение psql в объёме формата дампа (тестовая утилита).
/// </summary>
internal static class DbDumpRestorer
{
    /// <summary>
    /// Применяет файл дампа к базе данных.
    /// </summary>
    internal static async Task RestoreAsync(NpgsqlConnection connection, string dumpPath, CancellationToken cancellationToken)
    {
        string[] lines = await File.ReadAllLinesAsync(dumpPath, System.Text.Encoding.UTF8, cancellationToken);
        List<string> batch = [];
        int index = 0;

        while (index < lines.Length)
        {
            string line = lines[index];

            if (line.StartsWith("COPY ", StringComparison.Ordinal) &&
                line.EndsWith(") FROM STDIN;", StringComparison.Ordinal))
            {
                await ExecuteBatchAsync(connection, batch, cancellationToken).ConfigureAwait(false);
                batch.Clear();

                string copyCommand = line[..^1];
                System.Text.StringBuilder data = new();
                index++;

                while (index < lines.Length && lines[index] != "\\.")
                {
                    // Формат COPY: строки завершаются \n независимо от ОС
                    data.Append(lines[index]).Append('\n');
                    index++;
                }

                index++; // маркер конца данных

                using TextWriter writer = await connection
                    .BeginTextImportAsync(copyCommand, cancellationToken)
                    .ConfigureAwait(false);
                await writer.WriteAsync(data.ToString()).ConfigureAwait(false);

                continue;
            }

            batch.Add(line);
            index++;
        }

        await ExecuteBatchAsync(connection, batch, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Выполняет пакет обычных операторов одним multi-statement вызовом.</summary>
    private static async Task ExecuteBatchAsync(NpgsqlConnection connection, List<string> batch, CancellationToken cancellationToken)
    {
        string sql = string.Join('\n', batch).Trim();

        if (sql.Length == 0)
        {
            return;
        }

        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        batch.Clear();
    }
}
