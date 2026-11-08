using Npgsql;
using WebShelf.Classes.DB;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты проверки регистрационных пермитов (RegistrationPermitChecker):
/// чистые тесты построения результата по счётчику и интеграционные тесты
/// на реальном PostgreSQL 14+ (применяется настоящий файл-каркас
/// db/webshelf_skeleton.sql, таблица webshelf.registration_permits).
/// Интеграционные тесты выполняются только при заданной переменной окружения
/// <c>WEBSHELF_TEST_PG</c>, иначе пропускаются (как DbSchemaIntegrationTests).
/// </summary>
public class RegistrationPermitCheckerTests
{
    private const string SchemaName = "webshelf";

    // --- Чистые тесты: построение результата по счётчику ---

    /// <summary>
    /// Счётчик null — пермит не найден в БД: результат NotFound,
    /// счётчик результата — 0.
    /// </summary>
    [Fact]
    public void FromCounter_NullCounter_NotFound()
    {
        RegistrationPermitCheckResult result = RegistrationPermitCheckResult.FromCounter(null);

        Assert.Equal(RegistrationPermitStatus.NotFound, result.Status);
        Assert.Equal(0, result.Counter);
        Assert.False(result.IsUsable);
    }

    /// <summary>
    /// Счётчик 0 — пермит найден, но исчерпан: результат Exhausted.
    /// </summary>
    [Fact]
    public void FromCounter_ZeroCounter_Exhausted()
    {
        RegistrationPermitCheckResult result = RegistrationPermitCheckResult.FromCounter(0);

        Assert.Equal(RegistrationPermitStatus.Exhausted, result.Status);
        Assert.Equal(0, result.Counter);
        Assert.False(result.IsUsable);
    }

    /// <summary>
    /// Счётчик больше нуля (граница 1) — пермит пригоден для подачи заявки.
    /// </summary>
    [Fact]
    public void FromCounter_PositiveCounter_Usable()
    {
        RegistrationPermitCheckResult result = RegistrationPermitCheckResult.FromCounter(1);

        Assert.Equal(RegistrationPermitStatus.Usable, result.Status);
        Assert.Equal(1, result.Counter);
        Assert.True(result.IsUsable);
    }

    /// <summary>
    /// Верхняя граница счётчика каркаса (255) — пермит пригоден.
    /// </summary>
    [Fact]
    public void FromCounter_MaximumCounter_Usable()
    {
        RegistrationPermitCheckResult result = RegistrationPermitCheckResult.FromCounter(255);

        Assert.Equal(RegistrationPermitStatus.Usable, result.Status);
        Assert.Equal(255, result.Counter);
        Assert.True(result.IsUsable);
    }

    /// <summary>
    /// Отрицательный счётчик невозможен по CHECK-ограничению каркаса,
    /// но defensive-логика относит его к исчерпанным, а не к пригодным.
    /// </summary>
    [Fact]
    public void FromCounter_NegativeCounter_Exhausted()
    {
        RegistrationPermitCheckResult result = RegistrationPermitCheckResult.FromCounter(-1);

        Assert.Equal(RegistrationPermitStatus.Exhausted, result.Status);
        Assert.False(result.IsUsable);
    }

    // --- Интеграционные тесты: реальный PostgreSQL ---

    /// <summary>
    /// Пермит найден, счётчик больше нуля — пермит пригоден для подачи заявки.
    /// </summary>
    [PostgresFact]
    public async Task CheckAsync_PermitFoundCounterPositive_ReturnsUsable()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            await InsertPermitAsync(database, "test-permit-usable", 3);

            RegistrationPermitChecker checker = new(database);
            RegistrationPermitCheckResult result = await checker.CheckAsync("test-permit-usable");

            Assert.True(result.IsUsable);
            Assert.Equal(RegistrationPermitStatus.Usable, result.Status);
            Assert.Equal(3, result.Counter);
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Пермит найден со счётчиком 1 (минимальный положительный) — пригоден.
    /// </summary>
    [PostgresFact]
    public async Task CheckAsync_PermitFoundCounterOne_ReturnsUsable()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            await InsertPermitAsync(database, "test-permit-last", 1);

            RegistrationPermitChecker checker = new(database);
            RegistrationPermitCheckResult result = await checker.CheckAsync("test-permit-last");

            Assert.True(result.IsUsable);
            Assert.Equal(1, result.Counter);
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Пермит найден, но счётчик равен нулю — пермит исчерпан,
    /// окно подачи заявки не открывается.
    /// </summary>
    [PostgresFact]
    public async Task CheckAsync_PermitFoundCounterZero_ReturnsExhausted()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            await InsertPermitAsync(database, "test-permit-exhausted", 0);

            RegistrationPermitChecker checker = new(database);
            RegistrationPermitCheckResult result = await checker.CheckAsync("test-permit-exhausted");

            Assert.False(result.IsUsable);
            Assert.Equal(RegistrationPermitStatus.Exhausted, result.Status);
            Assert.Equal(0, result.Counter);
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Пермита нет в БД — результат NotFound.
    /// </summary>
    [PostgresFact]
    public async Task CheckAsync_PermitNotFound_ReturnsNotFound()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            RegistrationPermitChecker checker = new(database);
            RegistrationPermitCheckResult result = await checker.CheckAsync("no-such-permit");

            Assert.False(result.IsUsable);
            Assert.Equal(RegistrationPermitStatus.NotFound, result.Status);
            Assert.Equal(0, result.Counter);
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Пустой пермит и пермит из одних пробелов трактуется как ненайденный —
    /// без обращения к БД (не проходит условия «найден и счётчик больше нуля»).
    /// </summary>
    [PostgresFact]
    public async Task CheckAsync_EmptyOrWhitespacePermit_ReturnsNotFound()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            RegistrationPermitChecker checker = new(database);

            RegistrationPermitCheckResult emptyResult = await checker.CheckAsync(string.Empty);
            RegistrationPermitCheckResult whitespaceResult = await checker.CheckAsync("   ");

            Assert.Equal(RegistrationPermitStatus.NotFound, emptyResult.Status);
            Assert.False(emptyResult.IsUsable);
            Assert.Equal(RegistrationPermitStatus.NotFound, whitespaceResult.Status);
            Assert.False(whitespaceResult.IsUsable);
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Введённый пермит обрезается по краям: совпадение с точным значением
    /// из БД находится и при лишних пробелах.
    /// </summary>
    [PostgresFact]
    public async Task CheckAsync_PermitWithSurroundingSpaces_TrimsAndFinds()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            await InsertPermitAsync(database, "test-permit-trim", 2);

            RegistrationPermitChecker checker = new(database);
            RegistrationPermitCheckResult result = await checker.CheckAsync("  test-permit-trim  ");

            Assert.True(result.IsUsable);
            Assert.Equal(2, result.Counter);
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Создаёт контекст теста: экземпляр Database на тестовую базу
    /// и временный каталог для дампов (каркас — настоящий файл поставки
    /// db/webshelf_skeleton.sql, копируется в вывод сборки).
    /// </summary>
    private static async Task<(Database Database, string WorkDirectory)> CreateTestContextAsync(
        DbTestHelpers.TestDatabaseLease lease)
    {
        string workDirectory = Path.Combine(Path.GetTempPath(), $"ws_permit_{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDirectory);

        string skeletonPath = Path.Combine(AppContext.BaseDirectory, "db", "webshelf_skeleton.sql");
        Assert.True(File.Exists(skeletonPath), $"Файл каркаса не скопирован в вывод: {skeletonPath}");

        NpgsqlConnectionStringBuilder admin = DbTestHelpers.ParseAdminConnectionString();

        Database database = DbTestHelpers.CreateDatabase(
            admin.Host ?? "localhost",
            admin.Port is > 0 ? admin.Port : 5432,
            lease.DatabaseName,
            admin.Username ?? "postgres",
            admin.Password ?? string.Empty,
            admin.SslMode);

        SchemaBootstrapperOptions options = new(
            SchemaName,
            skeletonPath,
            Path.Combine(workDirectory, "dumps"),
            DumpRetentionDays: 90,
            AutoSchemaReset: false);

        // Каркас применяется до вставки тестовых данных: таблица
        // webshelf.registration_permits создаётся файлом-каркасом
        Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options));

        return (database, workDirectory);
    }

    /// <summary>
    /// Вставляет тестовый пермит со счётчиком (параметризованный запрос;
    /// значения — константы теста).
    /// </summary>
    private static async Task InsertPermitAsync(Database database, string permit, int counter)
    {
        await using NpgsqlConnection connection = await database.OpenConnectionAsync();
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = "INSERT INTO webshelf.registration_permits (permit, counter) VALUES (@permit, @counter)";
        command.Parameters.AddWithValue("permit", permit);
        command.Parameters.AddWithValue("counter", counter);
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Удаляет временный каталог теста (неудача удаления не влияет на результат).
    /// </summary>
    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
            // Каталог дампов может быть ещё занят — не влияет на результат теста
        }
    }
}
