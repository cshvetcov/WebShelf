using Npgsql;
using WebShelf.Classes.DB;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Интеграционные тесты сервиса заявок на регистрацию (RegistrationRequestService +
/// webshelf.registration_requests) на реальном PostgreSQL 14+: проверка
/// уникальности контактных данных и подача заявки одной транзакцией (повторная
/// проверка пермита, вставка с фиксацией редакций политик и времени подачи UTC
/// с точностью до секунды, идентификатор УЗ AD — NULL, уменьшение счётчика
/// пермита только после вставки). Каждый тест работает в собственной
/// изолированной базе данных; каркас применяется реальным файлом репозитория
/// (webshelf_skeleton.sql v5) — заодно интеграционная проверка новой структуры
/// таблицы заявок парсером каркаса и DbBootstrapper. Действующие редакции
/// политик подменяются фейком (IPolicyContentSource). Тесты выполняются только
/// при заданной переменной окружения <c>WEBSHELF_TEST_PG</c>, иначе
/// пропускаются.
/// </summary>
public class RegistrationRequestServiceTests
{
    private const string SchemaName = "webshelf";

    /// <summary>
    /// Корень решения: ищется от каталога сборки вверх до WebShelf.slnx —
    /// файл каркаса берётся из репозитория (как в PolicyContentServiceTests).
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

    // --- Проверка уникальности контактных данных ---

    /// <summary>
    /// Пустая таблица заявок: оба контакта свободны (предупреждений нет).
    /// </summary>
    [PostgresFact]
    public async Task CheckContactsAsync_EmptyTable_BothContactsAvailable()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, RegistrationRequestService service, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            RegistrationContactCheckResult result = await service.CheckContactsAsync("user@mail.ru", "+7 (999) 123-45-67");

            Assert.False(result.EmailTaken);
            Assert.False(result.PhoneTaken);
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Заявка с таким e-mail и телефоном уже подана — оба контакта заняты;
    /// чужие контакты не влияют на результат.
    /// </summary>
    [PostgresFact]
    public async Task CheckContactsAsync_ExistingRequest_MarksContactsTaken()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, RegistrationRequestService service, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            await InsertRequestAsync(database, "Иванов", "Иван", "Иванович",
                "+7 (999) 111-22-33", "taken@mail.ru");

            RegistrationContactCheckResult taken = await service.CheckContactsAsync("taken@mail.ru", "+7 (999) 111-22-33");
            RegistrationContactCheckResult free = await service.CheckContactsAsync("other@mail.ru", "+7 (999) 444-55-66");

            Assert.True(taken.EmailTaken);
            Assert.True(taken.PhoneTaken);
            Assert.False(free.EmailTaken);
            Assert.False(free.PhoneTaken);
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// E-mail сравнивается без учёта регистра (хранится в нижнем регистре):
    /// проверка «User@Mail.RU» находит заявку, поданную как «user@mail.ru».
    /// </summary>
    [PostgresFact]
    public async Task CheckContactsAsync_EmailCaseInsensitive_MatchesStoredLowercase()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, RegistrationRequestService service, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            RegistrationApplication application = MakeApplication("user@Mail.RU", "+7 (999) 111-22-33");
            await InsertPermitAsync(database, application.Permit, 1);
            Assert.True((await service.SubmitAsync(application)).IsSuccess);

            RegistrationContactCheckResult result = await service.CheckContactsAsync("USER@mail.ru", string.Empty);

            Assert.True(result.EmailTaken);
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    // --- Подача заявки ---

    /// <summary>
    /// Успешная подача: заявка записана со всеми данными формы — ФИО
    /// (обрезанные значения), телефон, e-mail в нижнем регистре, действующие
    /// редакции политик, время подачи по UTC без долей секунды,
    /// идентификатор УЗ AD — NULL (заявка не принята, ожидает решения
    /// администратора); счётчик пермита уменьшен ровно на 1.
    /// </summary>
    [PostgresFact]
    public async Task SubmitAsync_ValidApplication_InsertsRowAndDecrementsPermit()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, RegistrationRequestService service, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            RegistrationApplication application = MakeApplication("  User@Mail.RU  ", "  +7 (999) 123-45-67  ");
            application = application with
            {
                LastName = "  Иванов  ",
                FirstName = "  Иван  ",
                Patronymic = "  Иванович  "
            };
            await InsertPermitAsync(database, application.Permit, 3);

            DateTime beforeUtc = DateTime.UtcNow.AddSeconds(-5);
            RegistrationSubmitResult result = await service.SubmitAsync(application);
            DateTime afterUtc = DateTime.UtcNow.AddSeconds(5);

            Assert.True(result.IsSuccess);
            Assert.True(result.RequestId > 0);

            await using NpgsqlConnection connection = await database.OpenConnectionAsync();
            await using NpgsqlCommand command = connection.CreateCommand();
            command.CommandText = """
                SELECT last_name, first_name, patronymic, phone, email,
                       personal_data_policy_version, cookie_policy_version,
                       submitted_at, ad_object_guid
                FROM webshelf.registration_requests WHERE id = @id
                """;
            command.Parameters.AddWithValue("id", result.RequestId);

            await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();

            Assert.True(await reader.ReadAsync());
            Assert.Equal("Иванов", reader.GetString(0));
            Assert.Equal("Иван", reader.GetString(1));
            Assert.Equal("Иванович", reader.GetString(2));
            Assert.Equal("+7 (999) 123-45-67", reader.GetString(3));
            Assert.Equal("user@mail.ru", reader.GetString(4));

            // Действующие редакции политик — из подмены IPolicyContentSource
            Assert.Equal(FakePolicyCurrentVersion, reader.GetInt32(5));
            Assert.Equal(FakePolicyCurrentVersion, reader.GetInt32(6));

            // Время подачи: UTC, без долей секунды, в момент подачи
            DateTime submittedAt = reader.GetDateTime(7);
            Assert.Equal(DateTimeKind.Utc, submittedAt.Kind);
            Assert.Equal(0, submittedAt.Millisecond);
            Assert.InRange(submittedAt, beforeUtc, afterUtc);

            // Идентификатор УЗ AD не заполняется: заявка не принята
            Assert.True(reader.IsDBNull(8));

            // Счётчик пермита уменьшен на 1 (3 → 2) — только после вставки
            Assert.Equal(2, await ReadPermitCounterAsync(database, application.Permit));
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Пермит не найден — заявка не записана, счётчик не менялся
    /// (результат PermitNotUsable).
    /// </summary>
    [PostgresFact]
    public async Task SubmitAsync_PermitNotFound_PermitNotUsableAndNothingWritten()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, RegistrationRequestService service, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            RegistrationApplication application = MakeApplication("user@mail.ru", "+7 (999) 123-45-67");

            RegistrationSubmitResult result = await service.SubmitAsync(application);

            Assert.Equal(RegistrationSubmitStatus.PermitNotUsable, result.Status);
            Assert.Equal(0L, await CountRequestsAsync(database));
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Пермит найден, но счётчик равен нулю (исчерпан) — заявка не записана
    /// (гонка: регистрации по пермиту закончились между проверкой и подачей).
    /// </summary>
    [PostgresFact]
    public async Task SubmitAsync_PermitExhausted_PermitNotUsableAndNothingWritten()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, RegistrationRequestService service, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            RegistrationApplication application = MakeApplication("user@mail.ru", "+7 (999) 123-45-67");
            await InsertPermitAsync(database, application.Permit, 0);

            RegistrationSubmitResult result = await service.SubmitAsync(application);

            Assert.Equal(RegistrationSubmitStatus.PermitNotUsable, result.Status);
            Assert.Equal(0L, await CountRequestsAsync(database));
            Assert.Equal(0, await ReadPermitCounterAsync(database, application.Permit));
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Заявка с таким e-mail уже подана — новая не записывается, счётчик
    /// пермита не тратится (дружелюбная диагностика до вставки).
    /// </summary>
    [PostgresFact]
    public async Task SubmitAsync_DuplicateEmail_EmailTakenAndPermitNotSpent()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, RegistrationRequestService service, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            RegistrationApplication first = MakeApplication("dup@mail.ru", "+7 (999) 111-22-33");
            await InsertPermitAsync(database, first.Permit, 5);
            Assert.True((await service.SubmitAsync(first)).IsSuccess);

            RegistrationApplication second = MakeApplication("dup@mail.ru", "+7 (999) 444-55-66");
            await InsertPermitAsync(database, second.Permit, 2);

            RegistrationSubmitResult result = await service.SubmitAsync(second);

            Assert.Equal(RegistrationSubmitStatus.EmailTaken, result.Status);
            Assert.Equal(1L, await CountRequestsAsync(database));
            Assert.Equal(2, await ReadPermitCounterAsync(database, second.Permit));
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Заявка с таким телефоном уже подана — новая не записывается, счётчик
    /// пермита не тратится.
    /// </summary>
    [PostgresFact]
    public async Task SubmitAsync_DuplicatePhone_PhoneTakenAndPermitNotSpent()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, RegistrationRequestService service, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            RegistrationApplication first = MakeApplication("first@mail.ru", "+7 (999) 111-22-33");
            await InsertPermitAsync(database, first.Permit, 5);
            Assert.True((await service.SubmitAsync(first)).IsSuccess);

            RegistrationApplication second = MakeApplication("second@mail.ru", "+7 (999) 111-22-33");
            await InsertPermitAsync(database, second.Permit, 2);

            RegistrationSubmitResult result = await service.SubmitAsync(second);

            Assert.Equal(RegistrationSubmitStatus.PhoneTaken, result.Status);
            Assert.Equal(1L, await CountRequestsAsync(database));
            Assert.Equal(2, await ReadPermitCounterAsync(database, second.Permit));
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    // --- Структура таблицы (каркас v5) ---

    /// <summary>
    /// Структура таблицы заявок соответствует задаче: birth_date отсутствует
    /// (излишний сбор ПД), patronymic NOT NULL, новые столбцы редакций
    /// политик и времени подачи NOT NULL, ad_object_guid nullable
    /// и допускает несколько NULL (непринятых заявок сколько угодно),
    /// повторная привязка одного objectGUID запрещена ограничением UNIQUE.
    /// </summary>
    [PostgresFact]
    public async Task Skeleton_RegistrationRequestsStructure_MatchesRequirements()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, RegistrationRequestService service, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            // birth_date убран из структуры (излишний сбор ПД)
            Assert.Equal(0L, await ExecuteScalarLongAsync(database,
                "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'registration_requests' AND column_name = 'birth_date'"));
            Assert.Equal(1L, await ExecuteScalarLongAsync(database,
                "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'registration_requests' AND column_name = 'patronymic' AND is_nullable = 'NO'"));
            Assert.Equal(1L, await ExecuteScalarLongAsync(database,
                "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'registration_requests' AND column_name = 'ad_object_guid' AND is_nullable = 'YES'"));
            Assert.Equal(1L, await ExecuteScalarLongAsync(database,
                "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'registration_requests' AND column_name = 'personal_data_policy_version' AND is_nullable = 'NO'"));
            Assert.Equal(1L, await ExecuteScalarLongAsync(database,
                "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'registration_requests' AND column_name = 'cookie_policy_version' AND is_nullable = 'NO'"));
            Assert.Equal(1L, await ExecuteScalarLongAsync(database,
                "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'webshelf' AND table_name = 'registration_requests' AND column_name = 'submitted_at' AND is_nullable = 'NO'"));

            // Несколько непринятых заявок (NULL) не конфликтуют
            await InsertRequestAsync(database, "Иванов", "Иван", "Иванович", "+7 (999) 111-22-33", "one@mail.ru");
            await InsertRequestAsync(database, "Петров", "Пётр", "Петрович", "+7 (999) 444-55-66", "two@mail.ru");
            Assert.Equal(2L, await CountRequestsAsync(database));

            // Повторная привязка одного objectGUID запрещена (одна УЗ AD —
            // одна заявка), привязка разных — допустима
            Guid adGuid = Guid.NewGuid();
            await ExecuteAsync(database,
                "UPDATE webshelf.registration_requests SET ad_object_guid = @guid WHERE email = 'one@mail.ru'", guidParam => guidParam.AddWithValue("guid", adGuid));
            await Assert.ThrowsAsync<PostgresException>(() =>
                ExecuteAsync(database,
                    "UPDATE webshelf.registration_requests SET ad_object_guid = @guid WHERE email = 'two@mail.ru'", guidParam => guidParam.AddWithValue("guid", adGuid)));
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    /// <summary>
    /// Сходимость каркаса v5: после применения к пустой БД повторное сравнение
    /// живой схемы с каркасом не находит расхождений (SchemaDiff.IsEmpty) —
    /// следующий старт приложения не запускает обновление структуры
    /// (нормализация типов — uuid, timestamptz, varchar — и ограничений
    /// UNIQUE сходится с тем, что сообщает сам PostgreSQL).
    /// </summary>
    [PostgresFact]
    public async Task Skeleton_AfterApply_MatchesLiveSchemaWithoutDiff()
    {
        await using DbTestHelpers.TestDatabaseLease lease = await DbTestHelpers.CreateTestDatabaseAsync();
        (Database database, RegistrationRequestService service, string workDirectory) = await CreateTestContextAsync(lease);

        try
        {
            string skeletonPath = Path.Combine(SolutionRoot, "WebShelf", "db", "webshelf_skeleton.sql");
            SchemaSkeleton skeleton = await SchemaSkeletonLoader.LoadAsync(skeletonPath, SchemaName, TestContext.Current.CancellationToken);

            await using NpgsqlConnection connection = await database.OpenConnectionAsync();
            LiveSchema liveSchema = await LiveSchemaReader.ReadAsync(connection, SchemaName, TestContext.Current.CancellationToken);

            SchemaComparison comparison = SchemaComparer.Compare(skeleton.Manifest, liveSchema);

            Assert.True(comparison.Diff.IsEmpty,
                $"Живая схема не совпадает с каркасом после применения: {comparison.Diff}");
        }
        finally
        {
            await database.DisposeAsync();
            TryDeleteDirectory(workDirectory);
        }
    }

    // --- Вспомогательные методы ---

    /// <summary>Номер «действующей редакции» из подмены IPolicyContentSource.</summary>
    private const int FakePolicyCurrentVersion = 7;

    /// <summary>
    /// Создаёт контекст теста: тестовая база с применённым каркасом репозитория
    /// и сервис заявок с подменой журнала политик (обе политики — «действующая
    /// редакция» с номером <see cref="FakePolicyCurrentVersion"/>).
    /// </summary>
    private static async Task<(Database Database, RegistrationRequestService Service, string WorkDirectory)> CreateTestContextAsync(
        DbTestHelpers.TestDatabaseLease lease)
    {
        string workDirectory = Path.Combine(Path.GetTempPath(), $"ws_requests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDirectory);

        string skeletonPath = Path.Combine(SolutionRoot, "WebShelf", "db", "webshelf_skeleton.sql");
        Assert.True(File.Exists(skeletonPath), $"Файл каркаса не найден: {skeletonPath}");

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

        Assert.True(await DbBootstrapper.EnsureSchemaAsync(database, options), "Каркас репозитория должен применяться к пустой БД");

        FakePolicyContentSource policies = new(
            current: new PolicyVersion(
                FakePolicyCurrentVersion,
                new DateTimeOffset(2026, 11, 11, 0, 0, 0, TimeSpan.Zero),
                "<h2>Текст политики</h2>",
                new string('a', 64)));

        RegistrationRequestService service = new(database, policies);

        return (database, service, workDirectory);
    }

    /// <summary>
    /// Собирает заявку с уникальными per-тест пермитом и контактами
    /// (значения по умолчанию могут переопределяться вызывающим тестом).
    /// </summary>
    private static RegistrationApplication MakeApplication(string email, string phone)
        => new("Иванов", "Иван", "Иванович", email, phone, $"permit-{Guid.NewGuid():N}");

    /// <summary>Вставляет тестовый пермит со счётчиком.</summary>
    private static async Task InsertPermitAsync(Database database, string permit, int counter)
    {
        await ExecuteAsync(database,
            "INSERT INTO webshelf.registration_permits (permit, counter) VALUES (@permit, @counter)",
            parameters =>
            {
                parameters.AddWithValue("permit", permit);
                parameters.AddWithValue("counter", counter);
            });
    }

    /// <summary>
    /// Вставляет заявку напрямую (обход сервиса): тестовые данные для
    /// проверок уникальности и структуры.
    /// </summary>
    private static async Task InsertRequestAsync(
        Database database, string lastName, string firstName, string patronymic, string phone, string email)
    {
        await ExecuteAsync(database,
            """
            INSERT INTO webshelf.registration_requests
                (last_name, first_name, patronymic, phone, email,
                 personal_data_policy_version, cookie_policy_version, submitted_at)
            VALUES (@lastName, @firstName, @patronymic, @phone, @email, 1, 1, now())
            """,
            parameters =>
            {
                parameters.AddWithValue("lastName", lastName);
                parameters.AddWithValue("firstName", firstName);
                parameters.AddWithValue("patronymic", patronymic);
                parameters.AddWithValue("phone", phone);
                parameters.AddWithValue("email", email);
            });
    }

    /// <summary>Возвращает счётчик пермита.</summary>
    private static async Task<int> ReadPermitCounterAsync(Database database, string permit)
    {
        await using NpgsqlConnection connection = await database.OpenConnectionAsync();
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = "SELECT counter FROM webshelf.registration_permits WHERE permit = @permit";
        command.Parameters.AddWithValue("permit", permit);

        object? raw = await command.ExecuteScalarAsync();

        return Convert.ToInt32(raw!, System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>Возвращает количество заявок в таблице.</summary>
    private static async Task<long> CountRequestsAsync(Database database)
        => await ExecuteScalarLongAsync(database, "SELECT COUNT(*) FROM webshelf.registration_requests");

    /// <summary>Выполняет скалярный запрос и возвращает long.</summary>
    private static async Task<long> ExecuteScalarLongAsync(Database database, string sql)
    {
        await using NpgsqlConnection connection = await database.OpenConnectionAsync();
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = sql;

        object? raw = await command.ExecuteScalarAsync();

        return raw is long count ? count : Convert.ToInt64(raw!, System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>Выполняет запрос без результата (с параметрами через делегат).</summary>
    private static async Task ExecuteAsync(Database database, string sql, Action<NpgsqlParameterCollection>? fillParameters = null)
    {
        await using NpgsqlConnection connection = await database.OpenConnectionAsync();
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = sql;
        fillParameters?.Invoke(command.Parameters);

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
