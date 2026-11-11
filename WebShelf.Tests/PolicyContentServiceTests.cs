using Npgsql;
using WebShelf.Classes.DB;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Интеграционные тесты журнала версий политик (PolicyContentService +
/// webshelf.policy_versions) на реальном PostgreSQL 14+: синхронизация
/// поставки с журналом (первое наполнение, идемпотентность, новая редакция,
/// защита от отката), чтение редакций и контроль целостности. Каждый тест
/// работает в собственной изолированной базе данных; каркас применяется
/// реальным файлом репозитория (webshelf_skeleton.sql v4) — заодно
/// интеграционная проверка новой таблицы парсером каркаса и DbBootstrapper.
/// Тесты выполняются только при заданной переменной окружения
/// <c>WEBSHELF_TEST_PG</c>, иначе пропускаются.
/// </summary>
public class PolicyContentServiceTests
{
    /// <summary>Код cookie-политики (PolicyCatalog).</summary>
    private const string CookiePolicy = "cookie";

    /// <summary>
    /// Корень решения: ищется от каталога сборки вверх до WebShelf.slnx —
    /// файлы репозитория (каркас) не копируются в вывод сборки тестов.
    /// </summary>
    private static string SolutionRoot
    {
        get
        {
            DirectoryInfo? directory = new(AppContext.BaseDirectory);

            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "WebShelf.slnx")))
            {
                directory = directory.Parent;
            }

            return directory is null
                ? throw new InvalidOperationException(
                    $"Корень решения не найден от {AppContext.BaseDirectory}: тест требует запуска из дерева репозитория.")
                : directory.FullName;
        }
    }

    /// <summary>
    /// Создаёт контекст теста: тестовая база с применённым каркасом репозитория
    /// и каталог поставки с текстами политик (управляемый тестом).
    /// </summary>
    /// <param name="lease">Аренда тестовой базы данных.</param>
    /// <returns>Экземпляр Database и путь каталога поставки.</returns>
    private static async Task<(Database Database, string DeliveryDirectory)> CreateContextAsync(
        DbTestHelpers.TestDatabaseLease lease)
    {
        string workDirectory = Path.Combine(Path.GetTempPath(), $"ws_it_{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDirectory);

        NpgsqlConnectionStringBuilder admin = DbTestHelpers.ParseAdminConnectionString();

        Database database = DbTestHelpers.CreateDatabase(
            admin.Host ?? "localhost",
            admin.Port is > 0 ? admin.Port : 5432,
            lease.DatabaseName,
            admin.Username ?? "postgres",
            admin.Password ?? string.Empty,
            admin.SslMode);

        string skeletonPath = Path.Combine(SolutionRoot, "WebShelf", "db", "webshelf_skeleton.sql");

        SchemaBootstrapperOptions options = new(
            "webshelf",
            skeletonPath,
            Path.Combine(workDirectory, "dumps"),
            DumpRetentionDays: 90,
            AutoSchemaReset: false);

        Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options), "Каркас репозитория должен применяться к пустой БД");

        string deliveryDirectory = Path.Combine(workDirectory, "policies");
        Directory.CreateDirectory(deliveryDirectory);

        return (database, deliveryDirectory);
    }

    /// <summary>Пишет текст cookie-политики в каталог поставки.</summary>
    private static async Task WriteCookiePolicyFileAsync(string deliveryDirectory, string text)
    {
        await File.WriteAllTextAsync(Path.Combine(deliveryDirectory, "cookie-policy.html"), text);
    }

    /// <summary>Пишет текст политики персональных данных в каталог поставки.</summary>
    private static async Task WritePersonalDataPolicyFileAsync(string deliveryDirectory, string text)
    {
        await File.WriteAllTextAsync(Path.Combine(deliveryDirectory, "personal-data-policy.html"), text);
    }

    /// <summary>Возвращает количество строк журнала для политики.</summary>
    private static async Task<long> CountRowsAsync(Database database, string policyCode)
    {
        await using NpgsqlConnection connection = await database.OpenConnectionAsync();
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM webshelf.policy_versions WHERE policy = @policy";
        command.Parameters.AddWithValue("policy", policyCode);

        object? result = await command.ExecuteScalarAsync();

        return result is long count ? count : Convert.ToInt64(result!, System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Первый запуск на пустом журнале: для каждой политики вставляется
    /// редакция №1; актуальные редакции совпадают с текстами поставки.
    /// </summary>
    [PostgresFact]
    public async Task Sync_EmptyJournal_InsertsFirstVersions()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string deliveryDirectory) = await CreateContextAsync(lease);

        try
        {
            await WriteCookiePolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2>");
            await WritePersonalDataPolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2>");

            PolicyContentService service = new(database, deliveryDirectory);

            Assert.True(await service.SyncFromDeliveryAsync(), "Первая синхронизация должна пройти");

            Assert.Equal(1, await CountRowsAsync(database, CookiePolicy));
            Assert.Equal(1, await CountRowsAsync(database, "personal-data"));

            PolicyVersion? current = await service.GetCurrentAsync(CookiePolicy);

            Assert.NotNull(current);
            Assert.Equal(1, current.Version);
            Assert.Equal("<h2>1. Общие положения</h2>", current.Content);
        }
        finally
        {
            await database.DisposeAsync();
            Directory.Delete(Path.GetDirectoryName(deliveryDirectory)!, recursive: true);
        }
    }

    /// <summary>
    /// Повторный запуск без изменения текста: новые редакции не создаются,
    /// синхронизация проходит успешно (идемпотентность).
    /// </summary>
    [PostgresFact]
    public async Task Sync_UnchangedText_DoesNotInsertNewVersions()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string deliveryDirectory) = await CreateContextAsync(lease);

        try
        {
            await WriteCookiePolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2>");
            await WritePersonalDataPolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2>");

            PolicyContentService service = new(database, deliveryDirectory);
            Assert.True(await service.SyncFromDeliveryAsync());
            Assert.True(await service.SyncFromDeliveryAsync(), "Повторная синхронизация без изменений должна пройти");

            Assert.Equal(1, await CountRowsAsync(database, CookiePolicy));

            PolicyVersion? current = await service.GetCurrentAsync(CookiePolicy);

            Assert.NotNull(current);
            Assert.Equal(1, current.Version);
        }
        finally
        {
            await database.DisposeAsync();
            Directory.Delete(Path.GetDirectoryName(deliveryDirectory)!, recursive: true);
        }
    }

    /// <summary>
    /// Изменение текста поставки: вставляется редакция №2, актуальной становится
    /// она; история содержит обе редакции от актуальной к первой.
    /// </summary>
    [PostgresFact]
    public async Task Sync_ChangedText_InsertsNextVersion()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string deliveryDirectory) = await CreateContextAsync(lease);

        try
        {
            await WriteCookiePolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2>");
            await WritePersonalDataPolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2>");

            PolicyContentService service = new(database, deliveryDirectory);
            Assert.True(await service.SyncFromDeliveryAsync());

            await WriteCookiePolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2><p>Добавлен абзац.</p>");

            Assert.True(await service.SyncFromDeliveryAsync());

            Assert.Equal(2, await CountRowsAsync(database, CookiePolicy));

            PolicyVersion? current = await service.GetCurrentAsync(CookiePolicy);

            Assert.NotNull(current);
            Assert.Equal(2, current.Version);
            Assert.Contains("Добавлен абзац", current.Content);

            IReadOnlyList<PolicyVersionSummary> history = await service.GetHistoryAsync(CookiePolicy);

            Assert.Equal(2, history.Count);
            Assert.Equal(2, history[0].Version);
            Assert.Equal(1, history[1].Version);
        }
        finally
        {
            await database.DisposeAsync();
            Directory.Delete(Path.GetDirectoryName(deliveryDirectory)!, recursive: true);
        }
    }

    /// <summary>
    /// Возврат текста к ранее опубликованной редакции не создаёт новую строку
    /// (защита от отката публикации), актуальной остаётся последняя редакция.
    /// </summary>
    [PostgresFact]
    public async Task Sync_RevertedText_DoesNotInsertRollbackVersion()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string deliveryDirectory) = await CreateContextAsync(lease);

        try
        {
            const string firstText = "<h2>1. Общие положения</h2>";

            await WriteCookiePolicyFileAsync(deliveryDirectory, firstText);
            await WritePersonalDataPolicyFileAsync(deliveryDirectory, firstText);

            PolicyContentService service = new(database, deliveryDirectory);
            Assert.True(await service.SyncFromDeliveryAsync());

            await WriteCookiePolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2><p>Добавлен абзац.</p>");
            Assert.True(await service.SyncFromDeliveryAsync());

            // Откат поставки к первой редакции (например, перезапись старой сборкой)
            await WriteCookiePolicyFileAsync(deliveryDirectory, firstText);
            Assert.True(await service.SyncFromDeliveryAsync(), "Синхронизация отката должна пройти без вставки");

            Assert.Equal(2, await CountRowsAsync(database, CookiePolicy));

            PolicyVersion? current = await service.GetCurrentAsync(CookiePolicy);

            Assert.NotNull(current);
            Assert.Equal(2, current.Version);
        }
        finally
        {
            await database.DisposeAsync();
            Directory.Delete(Path.GetDirectoryName(deliveryDirectory)!, recursive: true);
        }
    }

    /// <summary>
    /// Отсутствие файла поставки — ошибка синхронизации (false): приложение
    /// обязано остановиться (fail-fast).
    /// </summary>
    [PostgresFact]
    public async Task Sync_MissingDeliveryFile_ReturnsFalse()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string deliveryDirectory) = await CreateContextAsync(lease);

        try
        {
            // Каталог поставки пуст: файлы текстов политик отсутствуют
            PolicyContentService service = new(database, deliveryDirectory);

            Assert.False(await service.SyncFromDeliveryAsync());
        }
        finally
        {
            await database.DisposeAsync();
            Directory.Delete(Path.GetDirectoryName(deliveryDirectory)!, recursive: true);
        }
    }

    /// <summary>
    /// Чтение архивной редакции: точный номер возвращает редакцию,
    /// несуществующий номер — null.
    /// </summary>
    [PostgresFact]
    public async Task GetVersion_ReturnsArchivedAndNullForUnknownVersion()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string deliveryDirectory) = await CreateContextAsync(lease);

        try
        {
            await WriteCookiePolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2>");
            await WritePersonalDataPolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2>");

            PolicyContentService service = new(database, deliveryDirectory);
            Assert.True(await service.SyncFromDeliveryAsync());

            await WriteCookiePolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2><p>Добавлен абзац.</p>");
            Assert.True(await service.SyncFromDeliveryAsync());

            PolicyVersion? archived = await service.GetVersionAsync(CookiePolicy, 1);

            Assert.NotNull(archived);
            Assert.Equal(1, archived.Version);
            Assert.Equal("<h2>1. Общие положения</h2>", archived.Content);

            Assert.Null(await service.GetVersionAsync(CookiePolicy, 9));
        }
        finally
        {
            await database.DisposeAsync();
            Directory.Delete(Path.GetDirectoryName(deliveryDirectory)!, recursive: true);
        }
    }

    /// <summary>
    /// Контроль целостности: изменение текста редакции напрямую в БД (мимо
    /// журнала) обнаруживается контрольной суммой — чтение выбрасывает
    /// PolicyContentIntegrityException.
    /// </summary>
    [PostgresFact]
    public async Task GetVersion_TamperedContent_ThrowsIntegrityException()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string deliveryDirectory) = await CreateContextAsync(lease);

        try
        {
            await WriteCookiePolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2>");
            await WritePersonalDataPolicyFileAsync(deliveryDirectory, "<h2>1. Общие положения</h2>");

            PolicyContentService service = new(database, deliveryDirectory);
            Assert.True(await service.SyncFromDeliveryAsync());

            // Подмена текста редакции в обход журнала
            await using NpgsqlConnection connection = await database.OpenConnectionAsync();
            await using NpgsqlCommand command = connection.CreateCommand();
            command.CommandText = "UPDATE webshelf.policy_versions SET content = '<h2>Подменённый текст</h2>' WHERE policy = @policy AND version = 1";
            command.Parameters.AddWithValue("policy", CookiePolicy);
            await command.ExecuteNonQueryAsync();

            PolicyContentIntegrityException? exception =
                await Record.ExceptionAsync(() => service.GetVersionAsync(CookiePolicy, 1)) as PolicyContentIntegrityException;

            Assert.NotNull(exception);
        }
        finally
        {
            await database.DisposeAsync();
            Directory.Delete(Path.GetDirectoryName(deliveryDirectory)!, recursive: true);
        }
    }
}
