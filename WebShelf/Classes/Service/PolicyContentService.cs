using Npgsql;
using WebShelf.Classes.DB;

namespace WebShelf.Classes.Service;

/// <summary>
/// Журнал версий политик обработки данных (таблица <c>webshelf.policy_versions</c>):
/// синхронизация текстов поставки с журналом при старте приложения и чтение
/// редакций для страниц политик и баннера согласия. Регистрируется в DI как
/// singleton (готовый экземпляр, как RegistrationPermitChecker) и публикуется
/// потребителям через <see cref="IPolicyContentSource"/>.
/// </summary>
/// <remarks>
/// <para>
/// Синхронизация при старте (<see cref="SyncFromDeliveryAsync"/>) — авторский
/// источник текста: файлы поставки <c>Content/Policies/*.html</c>; журнал БД —
/// рантайм-источник страниц. Текст читается, канонизируется (LF, без BOM),
/// вычисляется SHA-256 и сравнивается с последней строкой журнала политики:
/// не изменился — ничего не происходит; изменился — вставляется следующая
/// редакция (append-only: строки журнала никогда не обновляются и не удаляются).
/// Возврат текста, совпадающего с любой из существующих редакций, новую строку
/// не создаёт — защита от случайного отката публикации более старой поставкой.
/// </para>
/// <para>
/// Актуальные редакции и история кэшируются в памяти после синхронизации
/// (редакции меняются только при старте), поэтому отображение страницы политики
/// не обращается к БД. Архивные редакции читаются из БД напрямую.
/// Ошибка синхронизации останавливает приложение (fail-fast): без текста
/// политики информирование субъектов невозможно.
/// </para>
/// </remarks>
internal sealed class PolicyContentService : IPolicyContentSource
{
    private const string ClassName = "WebShelf.Classes.Service.PolicyContentService";

    /// <summary>Подключение к БД приложения (журнал webshelf.policy_versions).</summary>
    private readonly Database _database;

    /// <summary>Каталог поставки с текстами политик (Content/Policies).</summary>
    private readonly string _deliveryDirectory;

    /// <summary>Кэш актуальных редакций (пополняется синхронизацией при старте).</summary>
    private readonly Dictionary<string, PolicyVersion> _currentCache = new(StringComparer.Ordinal);

    /// <summary>Кэш сводок истории редакций (пополняется синхронизацией при старте).</summary>
    private readonly Dictionary<string, IReadOnlyList<PolicyVersionSummary>> _historyCache = new(StringComparer.Ordinal);

    /// <summary>
    /// Синхронизация кэшей. Обращения к кэшу короткие (чтение словаря),
    /// чтение БД выполняется вне блокировки, запись — под ней.
    /// </summary>
    private readonly object _cacheSync = new();

    /// <summary>
    /// Создаёт сервис журнала версий политик.
    /// </summary>
    /// <param name="database">Подключение к БД приложения.</param>
    /// <param name="deliveryDirectory">
    /// Каталог поставки с текстами политик; по умолчанию —
    /// <c>AppContext.BaseDirectory/Content/Policies</c>. Параметр предназначен
    /// интеграционным тестам (управляемый каталог с текстами).
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Возникает, если <paramref name="database"/> равен <see langword="null"/>.
    /// </exception>
    internal PolicyContentService(Database database, string? deliveryDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(database);

        _database = database;
        _deliveryDirectory = deliveryDirectory
            ?? Path.Combine(AppContext.BaseDirectory, PolicyCatalog.PoliciesRelativeDirectory);
    }

    /// <summary>
    /// Синхронизирует журнал версий политик с текстами поставки: для каждой
    /// известной политики читает файл, сравнивает контрольную сумму текста
    /// с журналом и добавляет новую редакцию при изменении. После прохода
    /// прогревает кэши актуальных редакций и истории. Вызывается из Program.Main
    /// синхронно с точкой старта (await) — до построения хоста приложения.
    /// </summary>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>
    /// <see langword="true"/> — журнал синхронизирован и кэши прогреты;
    /// <see langword="false"/> — ошибка (файл поставки не найден, вставка не
    /// выполнена): приложение обязано остановиться.
    /// </returns>
    internal async Task<bool> SyncFromDeliveryAsync(CancellationToken cancellationToken = default)
    {
        const string method = nameof(SyncFromDeliveryAsync);

        // Синхронизация — единственный момент, когда редакции могут измениться
        // (журнал пополняется только здесь): кэши сбрасываются и перезаливаются
        // по завершении прохода. Повторный вызов в том же экземпляре (тесты)
        // перечитывает журнал, а не остаётся на устаревших значениях
        lock (_cacheSync)
        {
            _currentCache.Clear();
            _historyCache.Clear();
        }

        foreach (PolicyDefinition definition in PolicyCatalog.Policies)
        {
            string filePath = Path.Combine(_deliveryDirectory, definition.FileName);

            if (!File.Exists(filePath))
            {
                Log.Error(
                    "Файл текста политики не найден в поставке. Policy={Policy}, Path={Path}. Class={Class}, Method={Method}",
                    definition.Code, filePath, ClassName, method);
                return false;
            }

            string rawText = await File.ReadAllTextAsync(filePath, System.Text.Encoding.UTF8, cancellationToken)
                .ConfigureAwait(false);
            string canonicalText = PolicyTextCanonicalizer.Canonicalize(rawText);
            string contentSha256 = PolicyTextCanonicalizer.ComputeSha256(canonicalText);

            (int lastVersion, string? lastSha256) = await ReadLastVersionAsync(definition.Code, cancellationToken)
                .ConfigureAwait(false);

            if (lastSha256 is not null && string.Equals(lastSha256, contentSha256, StringComparison.Ordinal))
            {
                Log.Debug(
                    "Текст политики не изменился — новая редакция не создаётся. Policy={Policy}, Version={Version}. Class={Class}, Method={Method}",
                    definition.Code, lastVersion, ClassName, method);
                continue;
            }

            if (lastSha256 is not null && await ShaExistsAsync(definition.Code, contentSha256, cancellationToken).ConfigureAwait(false))
            {
                Log.Warning(
                    "Текст политики совпадает с одной из ранее опубликованных редакций — публикация отката пропущена (защита от отката). Policy={Policy}, LastVersion={Version}. Class={Class}, Method={Method}",
                    definition.Code, lastVersion, ClassName, method);
                continue;
            }

            int? insertedVersion = await InsertVersionAsync(definition.Code, canonicalText, contentSha256, cancellationToken)
                .ConfigureAwait(false);

            if (insertedVersion is not int newVersion)
            {
                Log.Error(
                    "Не удалось добавить редакцию политики в журнал. Policy={Policy}, Sha256={Sha256}. Class={Class}, Method={Method}",
                    definition.Code, contentSha256, ClassName, method);
                return false;
            }

            Log.Information(
                "Добавлена редакция политики. Policy={Policy}, Version={Version}, Sha256={Sha256}. Class={Class}, Method={Method}",
                definition.Code, newVersion, contentSha256, ClassName, method);
        }

        // Прогрев кэшей: страницы политик и баннер согласия читают значения
        // без обращений к БД; пустой журнал после синхронизации — ошибка старта
        foreach (PolicyDefinition definition in PolicyCatalog.Policies)
        {
            PolicyVersion? current = await GetCurrentAsync(definition.Code, cancellationToken).ConfigureAwait(false);

            if (current is null)
            {
                Log.Error(
                    "После синхронизации журнал не содержит редакций политики. Policy={Policy}. Class={Class}, Method={Method}",
                    definition.Code, ClassName, method);
                return false;
            }

            await GetHistoryAsync(definition.Code, cancellationToken).ConfigureAwait(false);
        }

        return true;
    }

    /// <inheritdoc cref="IPolicyContentSource.GetCurrentAsync" />
    public async Task<PolicyVersion?> GetCurrentAsync(string policyCode, CancellationToken cancellationToken = default)
    {
        const string method = nameof(GetCurrentAsync);

        if (PolicyCatalog.TryFind(policyCode) is null)
        {
            Log.Error(
                "Неизвестный код политики при чтении актуальной редакции. Policy={Policy}. Class={Class}, Method={Method}",
                policyCode, ClassName, method);
            return null;
        }

        lock (_cacheSync)
        {
            if (_currentCache.TryGetValue(policyCode, out PolicyVersion? cached))
            {
                return cached;
            }
        }

        PolicyVersion? loaded = await ReadVersionRowAsync(policyCode, version: null, cancellationToken).ConfigureAwait(false);

        if (loaded is not null)
        {
            lock (_cacheSync)
            {
                _currentCache.TryAdd(policyCode, loaded);
            }
        }

        return loaded;
    }

    /// <inheritdoc cref="IPolicyContentSource.GetVersionAsync" />
    public async Task<PolicyVersion?> GetVersionAsync(string policyCode, int version, CancellationToken cancellationToken = default)
    {
        const string method = nameof(GetVersionAsync);

        if (PolicyCatalog.TryFind(policyCode) is null)
        {
            Log.Error(
                "Неизвестный код политики при чтении архивной редакции. Policy={Policy}. Class={Class}, Method={Method}",
                policyCode, ClassName, method);
            return null;
        }

        if (version < 1)
        {
            Log.Debug(
                "Запрошена редакция с номером меньше 1. Policy={Policy}, Version={Version}. Class={Class}, Method={Method}",
                policyCode, version, ClassName, method);
            return null;
        }

        return await ReadVersionRowAsync(policyCode, version, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc cref="IPolicyContentSource.GetHistoryAsync" />
    public async Task<IReadOnlyList<PolicyVersionSummary>> GetHistoryAsync(string policyCode, CancellationToken cancellationToken = default)
    {
        const string method = nameof(GetHistoryAsync);

        if (PolicyCatalog.TryFind(policyCode) is null)
        {
            Log.Error(
                "Неизвестный код политики при чтении истории редакций. Policy={Policy}. Class={Class}, Method={Method}",
                policyCode, ClassName, method);
            return [];
        }

        lock (_cacheSync)
        {
            if (_historyCache.TryGetValue(policyCode, out IReadOnlyList<PolicyVersionSummary>? cached))
            {
                return cached;
            }
        }

        List<PolicyVersionSummary> summaries = [];

        await using NpgsqlConnection connection = await _database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT version, effective_from, content_sha256
            FROM webshelf.policy_versions
            WHERE policy = @policy
            ORDER BY version DESC
            """;
        command.Parameters.AddWithValue("policy", policyCode);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            summaries.Add(new PolicyVersionSummary(
                reader.GetInt32(0),
                ReadUtcDateTimeOffset(reader, 1),
                reader.GetString(2)));
        }

        IReadOnlyList<PolicyVersionSummary> history = summaries.AsReadOnly();

        lock (_cacheSync)
        {
            _historyCache.TryAdd(policyCode, history);
        }

        return history;
    }

    /// <summary>
    /// Читает строку редакции из журнала: <paramref name="version"/> равен
    /// <see langword="null"/> — актуальная (MAX(version)), иначе — точная
    /// редакция. Проверяет контрольную сумму хранимого текста: несовпадение
    /// с <c>content_sha256</c> строки означает изменение текста вне журнала.
    /// </summary>
    /// <param name="policyCode">Код политики.</param>
    /// <param name="version">Номер редакции или null для актуальной.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Редакция или <see langword="null"/>, если строки нет.</returns>
    /// <exception cref="PolicyContentIntegrityException">
    /// Возникает при несовпадении контрольной суммы хранимого текста.
    /// </exception>
    private async Task<PolicyVersion?> ReadVersionRowAsync(string policyCode, int? version, CancellationToken cancellationToken)
    {
        const string method = nameof(ReadVersionRowAsync);

        await using NpgsqlConnection connection = await _database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = connection.CreateCommand();

        // Две формы запроса вместо единой с (@version IS NULL OR ...): PostgreSQL
        // не выводит тип параметра в контексте IS NULL (ошибка 42P08)
        command.CommandText = version is null
            ? """
              SELECT version, effective_from, content, content_sha256
              FROM webshelf.policy_versions
              WHERE policy = @policy
              ORDER BY version DESC
              LIMIT 1
              """
            : """
              SELECT version, effective_from, content, content_sha256
              FROM webshelf.policy_versions
              WHERE policy = @policy AND version = @version
              ORDER BY version DESC
              LIMIT 1
              """;
        command.Parameters.AddWithValue("policy", policyCode);

        if (version is not null)
        {
            command.Parameters.AddWithValue("version", version);
        }

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        int rowVersion = reader.GetInt32(0);
        DateTimeOffset effectiveFrom = ReadUtcDateTimeOffset(reader, 1);
        string content = reader.GetString(2);
        string storedSha256 = reader.GetString(3);

        // Канонизация идемпотентна: сумма пересчитывается из хранимого текста
        string actualSha256 = PolicyTextCanonicalizer.ComputeSha256(PolicyTextCanonicalizer.Canonicalize(content));

        if (!string.Equals(actualSha256, storedSha256, StringComparison.Ordinal))
        {
            Log.Error(
                "Нарушение целостности редакции политики: контрольная сумма текста не совпадает со строкой журнала. Policy={Policy}, Version={Version}, Expected={Expected}, Actual={Actual}. Class={Class}, Method={Method}",
                policyCode, rowVersion, storedSha256, actualSha256, ClassName, method);
            throw new PolicyContentIntegrityException(
                $"Контрольная сумма редакции №{rowVersion} политики '{policyCode}' не совпадает со строкой журнала: текст изменён вне журнала.");
        }

        return new PolicyVersion(rowVersion, effectiveFrom, content, storedSha256);
    }

    /// <summary>
    /// Возвращает последнюю редакцию политики: номер и контрольную сумму.
    /// Для пустого журнала — (0, null).
    /// </summary>
    /// <param name="policyCode">Код политики.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Номер последней редакции и её контрольная сумма.</returns>
    private async Task<(int Version, string? Sha256)> ReadLastVersionAsync(string policyCode, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await _database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT version, content_sha256
            FROM webshelf.policy_versions
            WHERE policy = @policy
            ORDER BY version DESC
            LIMIT 1
            """;
        command.Parameters.AddWithValue("policy", policyCode);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            return (0, null);
        }

        return (reader.GetInt32(0), reader.GetString(1));
    }

    /// <summary>
    /// Проверяет существование редакции политики с контрольной суммой текста
    /// (защита от отката: повторная публикация ранее существовавшего текста).
    /// </summary>
    /// <param name="policyCode">Код политики.</param>
    /// <param name="contentSha256">Контрольная сумма текста.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns><see langword="true"/> — редакция с такой суммой существует.</returns>
    private async Task<bool> ShaExistsAsync(string policyCode, string contentSha256, CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = await _database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = """
            SELECT 1
            FROM webshelf.policy_versions
            WHERE policy = @policy AND content_sha256 = @contentSha256
            LIMIT 1
            """;
        command.Parameters.AddWithValue("policy", policyCode);
        command.Parameters.AddWithValue("contentSha256", contentSha256);

        object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);

        return result is int found && found == 1;
    }

    /// <summary>
    /// Вставляет следующую редакцию политики: номер = MAX(version)+1, дата
    /// вступления — текущий момент. Атомарный guard: вставка выполняется только
    /// при отсутствии редакции с такой же контрольной суммой (откат не публикуется);
    /// UNIQUE(policy, version) — страховка от гонки параллельных стартов.
    /// </summary>
    /// <param name="policyCode">Код политики.</param>
    /// <param name="canonicalText">Канонизированный текст редакции.</param>
    /// <param name="contentSha256">Контрольная сумма текста.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Номер вставленной редакции или <see langword="null"/> (не вставлена).</returns>
    private async Task<int?> InsertVersionAsync(string policyCode, string canonicalText, string contentSha256, CancellationToken cancellationToken)
    {
        const string method = nameof(InsertVersionAsync);

        try
        {
            await using NpgsqlConnection connection = await _database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using NpgsqlCommand command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO webshelf.policy_versions (policy, version, content, content_sha256)
                SELECT @policy,
                       COALESCE((SELECT MAX(version) FROM webshelf.policy_versions WHERE policy = @policy), 0) + 1,
                       @content,
                       @contentSha256
                WHERE NOT EXISTS (
                    SELECT 1 FROM webshelf.policy_versions
                    WHERE policy = @policy AND content_sha256 = @contentSha256
                )
                RETURNING version
                """;
            command.Parameters.AddWithValue("policy", policyCode);
            command.Parameters.AddWithValue("content", canonicalText);
            command.Parameters.AddWithValue("contentSha256", contentSha256);

            object? raw = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);

            return raw is int insertedVersion ? insertedVersion : null;
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            // Гонка с параллельным стартом второго экземпляра: редакцию вставил он.
            // Fail-fast: следующий старт увидит совпадающую сумму и пропустит вставку
            Log.Warning(
                ex,
                "Вставка редакции политики отклонена ограничением уникальности (гонка параллельных стартов). Policy={Policy}, Sha256={Sha256}. Class={Class}, Method={Method}",
                policyCode, contentSha256, ClassName, method);
            return null;
        }
    }

    /// <summary>
    /// Читает столбец timestamptz как момент UTC: Npgsql сопоставляет
    /// timestamptz с DateTime (Kind=Utc); DateTimeOffset собирается с нулевым
    /// смещением независимо от Kind значения.
    /// </summary>
    /// <param name="reader">Читатель строки журнала.</param>
    /// <param name="ordinal">Номер столбца с датой вступления в силу.</param>
    /// <returns>Момент UTC вступления редакции в силу.</returns>
    private static DateTimeOffset ReadUtcDateTimeOffset(NpgsqlDataReader reader, int ordinal)
    {
        DateTime utc = reader.GetDateTime(ordinal);

        return new DateTimeOffset(utc, TimeSpan.Zero);
    }
}
