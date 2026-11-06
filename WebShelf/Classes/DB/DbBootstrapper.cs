using Npgsql;

namespace WebShelf.Classes.DB;

/// <summary>Режим приведения живой схемы к каркасу.</summary>
internal enum SchemaApplyMode
{
    /// <summary>Полный сброс: DROP SCHEMA CASCADE → CREATE SCHEMA → каркас. Данные удаляются.</summary>
    FullReset,

    /// <summary>Обновление структуры: best-effort с сохранением данных, каскад только при удалении.</summary>
    StructureUpdate
}

/// <summary>
/// Оркестратор сервисной инфраструктуры БД: загрузка каркаса → сравнение со живой
/// схемой → обязательный дамп (если схема не пуста) → применение каркаса →
/// контрольная проверка → очистка дампов по retention.
/// </summary>
/// <remarks>
/// <para>
/// Вызывается после <c>DatabaseSection.TryInitDatabaseAsync</c> (создание
/// <see cref="Database"/> и проверка доступности) и до передачи управления
/// остальному приложению — синхронно с точки зрения старта (<c>await</c>):
/// приложение не начинает работу на «чужой» схеме. При несовпадении с каркасом
/// и выключенном автосбросе (<c>dbautoschemareset=false</c>, безопасное значение
/// по умолчанию) старт прерывается, данные не затрагиваются.
/// </para>
/// <para>
/// Жёсткое правило безопасности (риск R2): любые изменения структуры выполняются
/// только после полностью успешного дампа либо на пустой схеме. Ошибка дампа
/// блокирует изменения и останавливает приложение (fail-fast).
/// </para>
/// <para>
/// На время bootstrap берётся advisory lock PostgreSQL (риск R5) — сериализация
/// конкурирующих экземпляров приложения, работающих с одной БД под разными
/// учётными записями Windows (InstanceLock защищает одну учётную запись).
/// Лок привязан к сессии, поэтому весь bootstrap выполняется на одном соединении —
/// это одно логическая операция.
/// </para>
/// <para>
/// Политика v1: автоматика старта применяет Structure Update (максимальное
/// сохранение данных); полный сброс — путь пустой схемы и явного программного
/// вызова. После обновления допускаются только остаточные расхождения типов
/// столбцов (v1 не меняет типы автоматически); всё остальное — ошибка.
/// </para>
/// <para>
/// TODO (будущее): страница Администратора «Сброс БД к каркасу» / «Обновление
/// структуры БД» с двойным подтверждением, отображением последнего дампа,
/// обязательным созданием нового дампа перед действием и аудитом (кто, когда,
/// с какого IP). Программные методы <see cref="ResetToSkeletonAsync"/> и
/// <see cref="UpdateStructureAsync"/> — точка подключения этой страницы.
/// </para>
/// </remarks>
internal static class DbBootstrapper
{
    private const string ClassName = "WebShelf.Classes.DB.DbBootstrapper";

    /// <summary>Ключи advisory lock (двухцелочисленная форма pg_advisory_lock).</summary>
    private const int AdvisoryLockKey1 = 0x57_45_42_53; // «WEBS»

    private const int AdvisoryLockKey2 = 0x53_48_45_4C; // «SHEL»

    /// <summary>
    /// Обеспечивает соответствие структуры БД каркасу при старте приложения.
    /// </summary>
    /// <param name="database">Инициализированное подключение к БД.</param>
    /// <param name="options">Параметры сервисной инфраструктуры БД.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>
    /// <see langword="true"/>, если структура соответствует каркасу (сразу или после
    /// допустимого приведения); <see langword="false"/> — приложение не должно
    /// продолжать работу (fail-fast).
    /// </returns>
    internal static Task<bool> EnsureSchemaAsync(
        Database database,
        SchemaBootstrapperOptions options,
        CancellationToken cancellationToken = default)
    {
        // Автоматика старта: гейт dbautoschemareset обязателен, режим — Structure Update
        return BootstrapAsync(database, options, enforceAutoResetGate: true, SchemaApplyMode.StructureUpdate, cancellationToken);
    }

    /// <summary>
    /// Явный программный полный сброс БД к каркасу (сценарий G ТЗ): дамп непустой
    /// схемы, затем DROP SCHEMA CASCADE и применение каркаса. Все данные удаляются.
    /// </summary>
    /// <param name="database">Инициализированное подключение к БД.</param>
    /// <param name="options">Параметры сервисной инфраструктуры БД.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns><see langword="true"/> при успехе; <see langword="false"/> — изменения не выполнялись или не удалось привести схему к каркасу.</returns>
    internal static Task<bool> ResetToSkeletonAsync(
        Database database,
        SchemaBootstrapperOptions options,
        CancellationToken cancellationToken = default)
    {
        return BootstrapAsync(database, options, enforceAutoResetGate: false, SchemaApplyMode.FullReset, cancellationToken);
    }

    /// <summary>
    /// Явный программный вызов обновления структуры БД к каркасу (сценарий H ТЗ):
    /// дамп непустой схемы, затем best-effort приведение с сохранением данных
    /// и каскадным удалением только для объектов, отсутствующих в каркасе.
    /// </summary>
    /// <param name="database">Инициализированное подключение к БД.</param>
    /// <param name="options">Параметры сервисной инфраструктуры БД.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns><see langword="true"/> при успехе; <see langword="false"/> — изменения не выполнялись или не удалось привести схему к каркасу.</returns>
    internal static Task<bool> UpdateStructureAsync(
        Database database,
        SchemaBootstrapperOptions options,
        CancellationToken cancellationToken = default)
    {
        return BootstrapAsync(database, options, enforceAutoResetGate: false, SchemaApplyMode.StructureUpdate, cancellationToken);
    }

    /// <summary>
    /// Общий сценарий приведения схемы к каркасу.
    /// </summary>
    private static async Task<bool> BootstrapAsync(
        Database database,
        SchemaBootstrapperOptions options,
        bool enforceAutoResetGate,
        SchemaApplyMode applyMode,
        CancellationToken cancellationToken)
    {
        const string method = nameof(BootstrapAsync);

        ArgumentNullException.ThrowIfNull(database);
        ArgumentNullException.ThrowIfNull(options);

        // 1. Каркас: существует, читается, разбирается (риск R7)
        SchemaSkeleton skeleton;

        try
        {
            skeleton = await SchemaSkeletonLoader.LoadAsync(options.SkeletonPath, options.SchemaName, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Не удалось загрузить файл-каркас БД. SkeletonPath={SkeletonPath}, Schema={Schema}. Class={Class}, Method={Method}",
                options.SkeletonPath, options.SchemaName, ClassName, method);
            return false;
        }

        Log.Information(
            "Каркас БД загружен. SkeletonPath={SkeletonPath}, Schema={Schema}, SkeletonHash={SkeletonHash}, Tables={Tables}, Sequences={Sequences}, Indexes={Indexes}. Class={Class}, Method={Method}",
            skeleton.Path, options.SchemaName, skeleton.Sha256Hash,
            skeleton.Manifest.Tables.Count, skeleton.Manifest.Sequences.Count, skeleton.Manifest.Indexes.Count,
            ClassName, method);

        // Одно соединение на весь bootstrap: advisory lock привязан к сессии
        await using NpgsqlConnection connection = await database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        if (!await TryAcquireAdvisoryLockAsync(connection, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        try
        {
            // 2. Живая схема и сравнение
            LiveSchema live = await LiveSchemaReader.ReadAsync(connection, options.SchemaName, cancellationToken).ConfigureAwait(false);
            SchemaComparison comparison = SchemaComparer.Compare(skeleton.Manifest, live);

            if (!comparison.Matches)
            {
                Log.Warning(
                    "Структура БД не соответствует каркасу. Schema={Schema}, Diff={Diff}. Class={Class}, Method={Method}",
                    options.SchemaName, comparison.Diff.BuildSummary(), ClassName, method);
                Log.Debug(
                    "Детали расхождения структуры. Diff={DiffDetails}. Class={Class}, Method={Method}",
                    comparison.Diff.ToString(), ClassName, method);
            }

            // 3. Совпадает — изменения не требуются (сценарий A)
            if (comparison.Matches)
            {
                Log.Information(
                    "Структура БД соответствует каркасу. Host={Host}, Port={Port}, Database={Database}, Schema={Schema}. Class={Class}, Method={Method}",
                    database.Host, database.Port, database.DatabaseName, options.SchemaName, ClassName, method);
                DumpRetentionPolicy.Apply(options.DumpsDirectory, options.DumpRetentionDays, TimeProvider.System);
                return true;
            }

            // 4. Схема пуста — дамп не нужен, применяется каркас (сценарий D)
            if (live.IsEmpty)
            {
                Log.Information(
                    "Схема БД пуста — дамп пропущен, применяется каркас. Schema={Schema}. Class={Class}, Method={Method}",
                    options.SchemaName, ClassName, method);

                if (!await ApplySkeletonAsync(connection, skeleton, options, cancellationToken).ConfigureAwait(false))
                {
                    return false;
                }

                DumpRetentionPolicy.Apply(options.DumpsDirectory, options.DumpRetentionDays, TimeProvider.System);
                return true;
            }

            // 5. Расхождение на непустой схеме: гейт автосброса (сценарий C)
            if (enforceAutoResetGate && !options.AutoSchemaReset)
            {
                Log.Error(
                    "Структура БД не соответствует каркасу. Автосброс отключён (dbautoschemareset=false), данные не затрагиваются, запуск блокирован. Host={Host}, Port={Port}, Database={Database}, Schema={Schema}, Diff={Diff}. Class={Class}, Method={Method}",
                    database.Host, database.Port, database.DatabaseName, options.SchemaName, comparison.Diff.BuildSummary(), ClassName, method);
                return false;
            }

            // 6. Обязательный дамп перед изменениями (риски R1, R2). Полный контекст — до деструктивного действия.
            Log.Warning(
                "Структура БД не соответствует каркасу и будет приведена к нему. Перед изменениями создаётся дамп. Host={Host}, Port={Port}, Database={Database}, Schema={Schema}, AutoSchemaReset={AutoSchemaReset}, Mode={Mode}, DumpPath={DumpsPath}, Diff={Diff}. Class={Class}, Method={Method}",
                database.Host, database.Port, database.DatabaseName, options.SchemaName,
                options.AutoSchemaReset, applyMode, options.DumpsDirectory, comparison.Diff.BuildSummary(),
                ClassName, method);

            DbDumper dumper = new(database);
            DbDumpResult dump;

            try
            {
                dump = await dumper.CreateDumpAsync(
                    options.SchemaName,
                    options.DumpsDirectory,
                    GetApplicationVersion(),
                    skeleton.Sha256Hash,
                    TimeProvider.System,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Причина и контекст залогированы DbDumper; изменения структуры не выполняются (fail-fast)
                Log.Error(
                    "Дамп не создан — изменения структуры БД не выполняются, приложение останавливается. Schema={Schema}, DumpsPath={DumpsPath}. Class={Class}, Method={Method}",
                    options.SchemaName, options.DumpsDirectory, ClassName, method);
                return false;
            }

            Log.Information(
                "Дамп перед изменением структуры создан. Path={Path}, SizeBytes={SizeBytes}. Class={Class}, Method={Method}",
                dump.FilePath, dump.SizeBytes, ClassName, method);

            // 7. Применение (сценарии B, G, H)
            try
            {
                if (applyMode is SchemaApplyMode.FullReset)
                {
                    await DbSkeletonApplier.ApplyFullResetAsync(
                        connection, options.SchemaName, skeleton.SqlText, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await DbSkeletonApplier.ApplyStructureUpdateAsync(
                        connection, options.SchemaName, skeleton.Manifest, comparison.Diff, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                Log.Error(
                    ex,
                    "Ошибка приведения структуры БД к каркасу — транзакция откачена, изменения не применены. Schema={Schema}, Mode={Mode}, DumpPath={DumpPath}. Class={Class}, Method={Method}",
                    options.SchemaName, applyMode, dump.FilePath, ClassName, method);
                return false;
            }

            // 8. Контрольная проверка
            LiveSchema liveAfter = await LiveSchemaReader.ReadAsync(connection, options.SchemaName, cancellationToken).ConfigureAwait(false);
            SchemaComparison comparisonAfter = SchemaComparer.Compare(skeleton.Manifest, liveAfter);

            bool onlyTypeDifferences = applyMode is SchemaApplyMode.StructureUpdate &&
                                       comparisonAfter.Diff.OnlyColumnTypeDifferences;

            if (!comparisonAfter.Matches && !onlyTypeDifferences)
            {
                Log.Error(
                    "После приведения структуры БД к каркасу сохраняются расхождения. Schema={Schema}, Diff={Diff}, DumpPath={DumpPath}. Class={Class}, Method={Method}",
                    options.SchemaName, comparisonAfter.Diff.BuildSummary(), dump.FilePath, ClassName, method);
                return false;
            }

            if (onlyTypeDifferences)
            {
                Log.Warning(
                    "Структура БД приведена к каркасу; сохраняются расхождения типов существующих столбцов (v1 не изменяет типы автоматически). Schema={Schema}, Diff={Diff}. Class={Class}, Method={Method}",
                    options.SchemaName, comparisonAfter.Diff.BuildSummary(), ClassName, method);
            }

            Log.Warning(
                "Структура БД приведена к каркасу (деструктивная или потенциально деструктивная операция выполнена). Host={Host}, Port={Port}, Database={Database}, Schema={Schema}, Mode={Mode}, DumpPath={DumpPath}. Class={Class}, Method={Method}",
                database.Host, database.Port, database.DatabaseName, options.SchemaName, applyMode, dump.FilePath, ClassName, method);

            DumpRetentionPolicy.Apply(options.DumpsDirectory, options.DumpRetentionDays, TimeProvider.System);
            return true;
        }
        finally
        {
            await ReleaseAdvisoryLockAsync(connection).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Применяет каркас к пустой схеме и проверяет результат.
    /// </summary>
    private static async Task<bool> ApplySkeletonAsync(
        NpgsqlConnection connection,
        SchemaSkeleton skeleton,
        SchemaBootstrapperOptions options,
        CancellationToken cancellationToken)
    {
        const string method = nameof(ApplySkeletonAsync);

        try
        {
            await DbSkeletonApplier.ApplyFullResetAsync(
                connection, options.SchemaName, skeleton.SqlText, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Ошибка применения каркаса к пустой схеме. Schema={Schema}. Class={Class}, Method={Method}",
                options.SchemaName, ClassName, method);
            return false;
        }

        LiveSchema liveAfter = await LiveSchemaReader.ReadAsync(connection, options.SchemaName, cancellationToken).ConfigureAwait(false);
        SchemaComparison comparisonAfter = SchemaComparer.Compare(skeleton.Manifest, liveAfter);

        if (!comparisonAfter.Matches)
        {
            Log.Error(
                "После применения каркаса к пустой схеме сохраняются расхождения. Schema={Schema}, Diff={Diff}. Class={Class}, Method={Method}",
                options.SchemaName, comparisonAfter.Diff.BuildSummary(), ClassName, method);
            return false;
        }

        Log.Information(
            "Каркас применён к пустой схеме БД. Schema={Schema}. Class={Class}, Method={Method}",
            options.SchemaName, ClassName, method);
        return true;
    }

    /// <summary>Захватывает advisory lock PostgreSQL на время bootstrap (риск R5).</summary>
    private static async Task<bool> TryAcquireAdvisoryLockAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        const string method = nameof(TryAcquireAdvisoryLockAsync);

        try
        {
            await using NpgsqlCommand command = connection.CreateCommand();
            command.CommandText = "SELECT pg_advisory_lock(@key1, @key2)";
            command.Parameters.AddWithValue("key1", AdvisoryLockKey1);
            command.Parameters.AddWithValue("key2", AdvisoryLockKey2);
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

            Log.Debug(
                "Advisory lock bootstrap захвачен. Class={Class}, Method={Method}",
                ClassName, method);
            return true;
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Не удалось захватить advisory lock (конкурирующий экземпляр выполняет bootstrap структуры БД или сбой соединения). Class={Class}, Method={Method}",
                ClassName, method);
            return false;
        }
    }

    /// <summary>Освобождает advisory lock; ошибки игнорируются — закрытие соединения снимет лок автоматически.</summary>
    private static async Task ReleaseAdvisoryLockAsync(NpgsqlConnection connection)
    {
        const string method = nameof(ReleaseAdvisoryLockAsync);

        try
        {
            await using NpgsqlCommand command = connection.CreateCommand();
            command.CommandText = "SELECT pg_advisory_unlock(@key1, @key2)";
            command.Parameters.AddWithValue("key1", AdvisoryLockKey1);
            command.Parameters.AddWithValue("key2", AdvisoryLockKey2);
            await command.ExecuteNonQueryAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log.Warning(
                ex,
                "Не удалось освободить advisory lock — соединение закрывается, лок снимется автоматически. Class={Class}, Method={Method}",
                ClassName, method);
        }
    }

    /// <summary>Возвращает версию приложения для метаданных дампа.</summary>
    private static string GetApplicationVersion()
    {
        return ThisAssembly.AssemblyInformationalVersion.Split('+')[0];
    }
}
