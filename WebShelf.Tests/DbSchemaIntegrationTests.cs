using Npgsql;
using WebShelf.Classes.DB;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Интеграционные тесты сервисной инфраструктуры БД (каркас, дамп, сброс /
/// обновление структуры) на реальном PostgreSQL 14+. Каждый тест работает
/// в собственной изолированной базе данных. Тесты выполняются только при
/// заданной переменной окружения <c>WEBSHELF_TEST_PG</c> (строка подключения
/// к серверу с правами создания баз данных), иначе пропускаются.
/// </summary>
/// <remarks>
/// Соответствуют обязательному минимуму ТЗ: пустая БД → применение каркаса;
/// расхождение + дамп + обновление; ошибка записи дампа → изменения запрещены;
/// автосброс отключён → fail-fast без изменения данных; обновление структуры
/// добавляет столбец без потери данных и удаляет лишнее каскадно; полный сброс;
/// round-trip дампа (восстановление на пустую схему).
/// </remarks>
public class DbSchemaIntegrationTests
{
    private const string SchemaName = "webshelf";

    /// <summary>Каркас v1: базовая структура (annotation — nullable для теста NULL в round-trip).</summary>
    private const string SkeletonV1 = """
        CREATE SCHEMA IF NOT EXISTS webshelf;

        CREATE TABLE webshelf.authors (
            id     bigint       NOT NULL,
            name   varchar(100) NOT NULL,
            CONSTRAINT authors_pkey PRIMARY KEY (id)
        );

        CREATE SEQUENCE webshelf.authors_id_seq AS bigint START WITH 1 INCREMENT BY 1;

        CREATE TABLE webshelf.books (
            id          bigint                   NOT NULL DEFAULT nextval('webshelf.authors_id_seq'::regclass),
            title       text                     NOT NULL,
            author_id   bigint                   NOT NULL,
            pages       integer                  NOT NULL DEFAULT 0,
            created_at  timestamp with time zone NOT NULL DEFAULT now(),
            annotation  text                     NULL,
            CONSTRAINT books_pkey PRIMARY KEY (id),
            CONSTRAINT books_author_fkey FOREIGN KEY (author_id) REFERENCES webshelf.authors(id) ON DELETE CASCADE,
            CONSTRAINT books_pages_check CHECK (pages > 0)
        );

        CREATE INDEX books_title_idx ON webshelf.books (title);
        """;

    /// <summary>Каркас v2: добавлен столбец extra_note и индекс по author_id.</summary>
    private const string SkeletonV2 = SkeletonV1 + """

        ALTER TABLE webshelf.books ADD COLUMN extra_note text NOT NULL DEFAULT '';

        CREATE INDEX books_author_idx ON webshelf.books (author_id);
        """;

    /// <summary>Каркас v1 с переименованным индексом (проверка замены индекса).</summary>
    private static string SkeletonV2Renamed => SkeletonV1.Replace("books_title_idx", "books_name_idx");

    /// <summary>
    /// Пустая база: каркас применяется без дампа, повторный старт — совпадение.
    /// </summary>
    [PostgresFact]
    public async Task EnsureSchema_EmptyDatabase_AppliesSkeletonWithoutDump()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, SchemaBootstrapperOptions options) = await CreateTestContextAsync(lease, SkeletonV1, autoReset: false);

        try
        {
            bool firstRun = await DbBootstrapper.EnsureSchemaAsync(database, options);
            Assert.True(firstRun, "Пустая БД: каркас должен применяться без дампа");

            await using NpgsqlConnection connection = await database.OpenConnectionAsync();
            LiveSchema live = await LiveSchemaReader.ReadAsync(connection, SchemaName, TestContext.Current.CancellationToken);
            Assert.True(live.SchemaExists);
            Assert.Equal(2, live.Tables.Count);
            Assert.Single(live.Sequences);
            Assert.Single(live.Indexes);

            // Повторный старт: структура совпадает, новых дампов нет
            bool secondRun = await DbBootstrapper.EnsureSchemaAsync(database, options);
            Assert.True(secondRun);
            Assert.Empty(ListDumpFiles(options.DumpsDirectory));
        }
        finally
        {
            await database.DisposeAsync();
        }
    }

    /// <summary>
    /// Расхождение при dbautoschemareset=false: fail-fast, данные не затрагиваются,
    /// дамп не создаётся.
    /// </summary>
    [PostgresFact]
    public async Task EnsureSchema_MismatchWithAutoResetDisabled_FailsFastAndKeepsData()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, SchemaBootstrapperOptions options) = await CreateTestContextAsync(lease, SkeletonV1, autoReset: false);

        try
        {
            Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options));
            await ExecuteAsync(database, "ALTER TABLE webshelf.books ADD COLUMN drift_column text");

            bool result = await DbBootstrapper.EnsureSchemaAsync(database, options);

            Assert.False(result, "Расхождение при отключённом автосбросе должно блокировать старт");
            Assert.Equal(1L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'books' AND column_name = 'drift_column'"));
            Assert.Empty(ListDumpFiles(options.DumpsDirectory));
        }
        finally
        {
            await database.DisposeAsync();
        }
    }

    /// <summary>
    /// Расхождение при dbautoschemareset=true: дамп создаётся, затем выполняется
    /// обновление структуры с сохранением данных (новый столбец добавлен, строки на месте).
    /// </summary>
    [PostgresFact]
    public async Task EnsureSchema_MismatchWithAutoReset_DumpsThenUpdatesPreservingData()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, SchemaBootstrapperOptions options) = await CreateTestContextAsync(lease, SkeletonV1, autoReset: true);

        try
        {
            Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options));
            await ExecuteAsync(database, "INSERT INTO webshelf.authors (id, name) VALUES (1, 'Автор первый')");
            await ExecuteAsync(database, "INSERT INTO webshelf.books (id, title, author_id, pages) VALUES (10, 'Книга о строительстве', 1, 320)");

            // Смена каркаса на v2 (новый столбец и индекс) — расхождение
            await File.WriteAllTextAsync(options.SkeletonPath, SkeletonV2);

            bool result = await DbBootstrapper.EnsureSchemaAsync(database, options);

            Assert.True(result, "Обновление структуры с автосбросом должно выполняться после дампа");

            string[] dumpFiles = ListDumpFiles(options.DumpsDirectory);
            Assert.Single(dumpFiles);

            Assert.Equal(1L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'books' AND column_name = 'annotation'"));
            Assert.Equal(1L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'webshelf' AND indexname = 'books_author_idx'"));
            Assert.Equal(1L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM webshelf.books WHERE title = 'Книга о строительстве'"));
        }
        finally
        {
            await database.DisposeAsync();
        }
    }

    /// <summary>
    /// Ошибка записи дампа (каталог недоступен) блокирует любые изменения структуры.
    /// </summary>
    [PostgresFact]
    public async Task EnsureSchema_DumpFailure_BlocksStructureChanges()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, SchemaBootstrapperOptions options) = await CreateTestContextAsync(lease, SkeletonV1, autoReset: true);

        try
        {
            Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options));
            await ExecuteAsync(database, "ALTER TABLE webshelf.books ADD COLUMN drift_column text");

            // Каталог дампов «занят» файлом — создание каталога завершится ошибкой
            string blockerPath = options.DumpsDirectory + ".blocker";
            await File.WriteAllTextAsync(blockerPath, string.Empty);

            try
            {
                // Точка отказа: путь дампов указывает на файл, а не каталог
                SchemaBootstrapperOptions brokenOptions = options with { DumpsDirectory = blockerPath };

                bool result = await DbBootstrapper.EnsureSchemaAsync(database, brokenOptions);

                Assert.False(result, "Ошибка дампа должна блокировать изменения структуры");

                // Схема не изменилась: столбец drift_column остался, данные нетронуты
                Assert.Equal(1L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'books' AND column_name = 'drift_column'"));
            }
            finally
            {
                File.Delete(blockerPath);
            }
        }
        finally
        {
            await database.DisposeAsync();
        }
    }

    /// <summary>
    /// Неподдерживаемые объекты (представление) блокируют дамп и изменения.
    /// </summary>
    [PostgresFact]
    public async Task EnsureSchema_UnsupportedObject_BlocksDumpAndChanges()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, SchemaBootstrapperOptions options) = await CreateTestContextAsync(lease, SkeletonV1, autoReset: true);

        try
        {
            Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options));
            await ExecuteAsync(database, "CREATE VIEW webshelf.legacy_view AS SELECT id FROM webshelf.authors");
            await File.WriteAllTextAsync(options.SkeletonPath, SkeletonV2);

            bool result = await DbBootstrapper.EnsureSchemaAsync(database, options);

            Assert.False(result, "Неподдерживаемые объекты должны блокировать дамп и изменения");
            Assert.Empty(ListDumpFiles(options.DumpsDirectory));
            Assert.Equal(0L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'books' AND column_name = 'extra_note'"));
        }
        finally
        {
            await database.DisposeAsync();
        }
    }

    /// <summary>
    /// Обновление структуры удаляет лишний столбец и индекс каскадно, данные сохраняются.
    /// </summary>
    [PostgresFact]
    public async Task EnsureSchema_UpdateDropsUnexpectedColumnAndIndex_Cascade()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, SchemaBootstrapperOptions options) = await CreateTestContextAsync(lease, SkeletonV2, autoReset: true);

        try
        {
            Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options));
            await ExecuteAsync(database, "INSERT INTO webshelf.authors (id, name) VALUES (1, 'Автор')");
            await ExecuteAsync(database, "INSERT INTO webshelf.books (id, title, author_id, pages) VALUES (10, 'Книга', 1, 100)");

            // Дрейф: лишний столбец и лишний индекс
            await ExecuteAsync(database, "ALTER TABLE webshelf.books ADD COLUMN legacy_code text");
            await ExecuteAsync(database, "CREATE INDEX books_legacy_idx ON webshelf.books (legacy_code)");

            // Смена каркаса: v2 без лишних объектов, но с переименованным индексом
            await File.WriteAllTextAsync(options.SkeletonPath, SkeletonV2Renamed);

            bool result = await DbBootstrapper.EnsureSchemaAsync(database, options);

            Assert.True(result);

            Assert.Equal(0L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'books' AND column_name = 'legacy_code'"));
            Assert.Equal(0L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'webshelf' AND indexname = 'books_legacy_idx'"));
            Assert.Equal(1L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'webshelf' AND indexname = 'books_name_idx'"));
            Assert.Equal(1L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM webshelf.books"));
        }
        finally
        {
            await database.DisposeAsync();
        }
    }

    /// <summary>
    /// Явный программный полный сброс: данные удаляются, структура воссоздаётся по каркасу.
    /// </summary>
    [PostgresFact]
    public async Task ResetToSkeleton_PopulatedDatabase_DestroysDataAndRebuilds()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, SchemaBootstrapperOptions options) = await CreateTestContextAsync(lease, SkeletonV1, autoReset: false);

        try
        {
            Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options));
            await ExecuteAsync(database, "INSERT INTO webshelf.authors (id, name) VALUES (1, 'Автор')");
            await ExecuteAsync(database, "ALTER TABLE webshelf.books ADD COLUMN drift_column text");

            bool result = await DbBootstrapper.ResetToSkeletonAsync(database, options);

            Assert.True(result);
            Assert.Single(ListDumpFiles(options.DumpsDirectory));
            Assert.Equal(0L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM webshelf.authors"));
            Assert.Equal(0L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'books' AND column_name = 'drift_column'"));

            // Повторный старт после сброса: структура совпадает с каркасом
            Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options));
        }
        finally
        {
            await database.DisposeAsync();
        }
    }

    /// <summary>
    /// Round-trip: дамп populated-схемы восстанавливается после DROP SCHEMA —
    /// структура и данные совпадают с исходными (требование ТЗ к полноте дампа).
    /// </summary>
    [PostgresFact]
    public async Task Dump_RoundTrip_RestoresStructureAndData()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, SchemaBootstrapperOptions options) = await CreateTestContextAsync(lease, SkeletonV1, autoReset: false);

        try
        {
            Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options));

            // Данные: NULL, табуляция, кириллица, несколько строк
            await ExecuteAsync(database, "INSERT INTO webshelf.authors (id, name) VALUES (1, 'Иванов'), (2, 'Петрова')");
            await ExecuteAsync(database, "INSERT INTO webshelf.books (id, title, author_id, pages, annotation) VALUES (10, 'Том с табуляцией\tвнутри', 1, 320, 'примечание'), (11, 'Черновик', 1, 1, NULL), (12, 'Смета', 2, 55, NULL)");

            DbDumper dumper = new(database);
            DbDumpResult dump = await dumper.CreateDumpAsync(
                SchemaName, options.DumpsDirectory, "test-version", "test-hash", TimeProvider.System, TestContext.Current.CancellationToken);

            Assert.True(File.Exists(dump.FilePath));
            Assert.True(dump.SizeBytes > 0);

            long authorsBefore = await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM webshelf.authors");
            long booksBefore = await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM webshelf.books");

            // Полная потеря схемы, затем восстановление из дампа
            await ExecuteAsync(database, "DROP SCHEMA webshelf CASCADE");

            await using NpgsqlConnection connection = await database.OpenConnectionAsync();
            await DbDumpRestorer.RestoreAsync(connection, dump.FilePath, TestContext.Current.CancellationToken);

            LiveSchema live = await LiveSchemaReader.ReadAsync(connection, SchemaName, TestContext.Current.CancellationToken);
            Assert.Equal(2, live.Tables.Count);
            Assert.Single(live.Sequences);
            Assert.Single(live.Indexes);
            Assert.Equal(0, live.UnsupportedObjectCount);

            TableDefinition books = live.Tables.Single(table => table.Name == "books");
            Assert.Equal(6, books.Columns.Count);

            Assert.Equal(authorsBefore, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM webshelf.authors"));
            Assert.Equal(booksBefore, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM webshelf.books"));
            Assert.Equal(1L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM webshelf.books WHERE title = 'Том с табуляцией\tвнутри'"));

            // Ограничения восстановлены: CHECK отклоняет нарушающее значение
            await Assert.ThrowsAsync<PostgresException>(() =>
                ExecuteAsync(database, "INSERT INTO webshelf.books (id, title, author_id, pages) VALUES (99, 'x', 1, -1)"));
        }
        finally
        {
            await database.DisposeAsync();
        }
    }

    /// <summary>
    /// Остаточное расхождение типов столбцов допускается после обновления
    /// (v1 не меняет типы автоматически), остальные расхождения — нет.
    /// </summary>
    [PostgresFact]
    public async Task EnsureSchema_TypeOnlyMismatch_ToleratedAfterUpdate()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, SchemaBootstrapperOptions options) = await CreateTestContextAsync(lease, SkeletonV1, autoReset: true);

        try
        {
            Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options));

            // Дрейф типа: pages integer → bigint
            await ExecuteAsync(database, "ALTER TABLE webshelf.books ALTER COLUMN pages TYPE bigint");

            bool result = await DbBootstrapper.EnsureSchemaAsync(database, options);

            Assert.True(result, "Остаточное расхождение только типов должно допускаться");
            // Тип не изменён автоматически
            Assert.Equal(1L, await ExecuteScalarAsync(database, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'books' AND column_name = 'pages' AND data_type = 'bigint'"));
        }
        finally
        {
            await database.DisposeAsync();
        }
    }

    /// <summary>
    /// Создаёт контекст теста: файл каркаса во временном каталоге, параметры
    /// с временным каталогом дампов и экземпляр Database на тестовую базу.
    /// </summary>
    private static async Task<(Database Database, SchemaBootstrapperOptions Options)> CreateTestContextAsync(
        DbTestHelpers.TestDatabaseLease lease,
        string skeletonSql,
        bool autoReset)
    {
        string workDirectory = Path.Combine(Path.GetTempPath(), $"ws_it_{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDirectory);

        string skeletonPath = Path.Combine(workDirectory, "skeleton.sql");
        await File.WriteAllTextAsync(skeletonPath, skeletonSql);

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
            AutoSchemaReset: autoReset);

        return (database, options);
    }

    /// <summary>Перечисляет файлы дампов в каталоге (безопасно при отсутствии каталога).</summary>
    private static string[] ListDumpFiles(string dumpsDirectory)
    {
        return Directory.Exists(dumpsDirectory)
            ? Directory.GetFiles(dumpsDirectory, "webshelf_dump_*.sql")
            : [];
    }

    /// <summary>Выполняет SQL на тестовой базе (временные каталоги чистит тест).</summary>
    private static async Task ExecuteAsync(Database database, string sql)
    {
        await using NpgsqlConnection connection = await database.OpenConnectionAsync();
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>Выполняет скалярный SQL-запрос на тестовой базе.</summary>
    private static async Task<long> ExecuteScalarAsync(Database database, string sql)
    {
        await using NpgsqlConnection connection = await database.OpenConnectionAsync();
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = sql;
        object? result = await command.ExecuteScalarAsync();
        return result is long count ? count : Convert.ToInt64(result, System.Globalization.CultureInfo.InvariantCulture);
    }
}
