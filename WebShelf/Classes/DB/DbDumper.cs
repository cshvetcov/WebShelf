using System.Text;
using Npgsql;

namespace WebShelf.Classes.DB;

/// <summary>
/// Результат успешно созданного дампа.
/// </summary>
/// <param name="FilePath">Полный путь к файлу дампа.</param>
/// <param name="SizeBytes">Размер файла в байтах.</param>
/// <param name="UtcCreated">Метка времени создания (UTC, закодирована в имени файла).</param>
internal sealed record DbDumpResult(string FilePath, long SizeBytes, DateTime UtcCreated);

/// <summary>
/// Создание дампа БД (структура + данные) средствами Npgsql — без внешних утилит
/// (<c>pg_dump</c>/<c>psql</c> на хосте не требуются).
/// </summary>
/// <remarks>
/// <para>
/// Формат — текстовый SQL: DDL объектов схемы, затем данные таблиц командами
/// <c>COPY … FROM STDIN</c> (текстовый формат PostgreSQL), метаданные — в комментариях
/// заголовка. Дамп применяется вручную (например, через psql) как обычный скрипт.
/// </para>
/// <para>
/// Порядок объектов восстановления: последовательности → таблицы со столбцами
/// и ограничениями (кроме FK) → данные → владение последовательностями → внешние
/// ключи → индексы. DDL и данные читаются в одной транзакции REPEATABLE READ —
/// согласованный снимок. Запись идёт во временный файл с последующим атомарным
/// перемещением; при любой ошибке временный файл удаляется, исключение пробрасывается
/// вызывающему (изменения структуры при ошибке дампа не выполняются — риск R2).
/// </para>
/// <para>
/// Дамп ограничен поддерживаемым набором объектов (таблицы, столбцы, PK/FK/UNIQUE/CHECK,
/// sequences, индексы). При обнаружении в схеме объектов вне набора дамп не создаётся
/// (защита от неполного дампа, риск R3).
/// </para>
/// </remarks>
internal sealed class DbDumper(Database database)
{
    private const string ClassName = "WebShelf.Classes.DB.DbDumper";

    /// <summary>Версия формата дампа (для будущих изменений формата).</summary>
    private const int DumpFormatVersion = 1;

    /// <summary>Максимальные значения последовательностей по типам данных (умолчания PostgreSQL).</summary>
    private static readonly Dictionary<string, long> SequenceTypeMaxValues = new()
    {
        ["smallint"] = 32767,
        ["integer"] = 2147483647,
        ["bigint"] = 9223372036854775807,
    };

    /// <summary>
    /// Создаёт дамп схемы (структура + данные) в каталоге дампов.
    /// Имя файла содержит метку времени UTC. Схема должна быть непустой.
    /// </summary>
    /// <param name="schemaName">Имя схемы.</param>
    /// <param name="dumpsDirectory">Каталог дампов (создаётся при отсутствии).</param>
    /// <param name="applicationVersion">Версия приложения для метаданных дампа.</param>
    /// <param name="skeletonSha256Hash">Хеш текущего файла-каркаса (SHA-256) для метаданных.</param>
    /// <param name="timeProvider">Поставщик времени (метка времени в имени файла).</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Описание созданного дампа.</returns>
    /// <exception cref="DbDumpException">Схема пуста, содержит неподдерживаемые объекты или произошла ошибка записи.</exception>
    internal async Task<DbDumpResult> CreateDumpAsync(
        string schemaName,
        string dumpsDirectory,
        string applicationVersion,
        string skeletonSha256Hash,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        const string method = nameof(CreateDumpAsync);

        ArgumentException.ThrowIfNullOrWhiteSpace(schemaName);
        ArgumentException.ThrowIfNullOrWhiteSpace(dumpsDirectory);
        ArgumentNullException.ThrowIfNull(timeProvider);

        string tempPath = string.Empty;

        try
        {
            Directory.CreateDirectory(dumpsDirectory);

            await using NpgsqlConnection connection = await database.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

            // Согласованный снимок схемы и данных: одна транзакция REPEATABLE READ
            await using NpgsqlTransaction transaction =
                await connection.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
            LiveSchema live = await LiveSchemaReader.ReadAsync(connection, schemaName, cancellationToken).ConfigureAwait(false);

            if (live.IsEmpty)
            {
                throw new DbDumpException($"Схема «{schemaName}» пуста — дамп не создаётся.");
            }

            if (live.UnsupportedObjectCount > 0)
            {
                throw new DbDumpException(
                    $"Схема «{schemaName}» содержит объекты, не входящие в поддерживаемый набор дампа " +
                    $"({live.UnsupportedObjectCount} шт.: {live.UnsupportedObjectSummary}). " +
                    "Дамп был бы неполным — создание прервано.");
            }

            DateTime utcCreated = timeProvider.GetUtcNow().UtcDateTime;
            string finalPath = Path.Combine(dumpsDirectory, DbDumpFile.BuildFileName(utcCreated));
            tempPath = finalPath + ".tmp";

            long sizeBytes = await WriteDumpFileAsync(
                connection, live, tempPath, schemaName, applicationVersion, skeletonSha256Hash, utcCreated, cancellationToken)
                .ConfigureAwait(false);

            // Атомарное перемещение: файл дампа появляется в каталоге только полностью записанным
            File.Move(tempPath, finalPath);

            Log.Information(
                "Дамп БД создан. Path={Path}, SizeBytes={SizeBytes}, Tables={Tables}, Sequences={Sequences}, Indexes={Indexes}. Class={Class}, Method={Method}",
                finalPath, sizeBytes, live.Tables.Count, live.Sequences.Count, live.Indexes.Count, ClassName, method);

            return new DbDumpResult(finalPath, sizeBytes, utcCreated);
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Ошибка создания дампа БД. Schema={Schema}, DumpsPath={DumpsPath}. Class={Class}, Method={Method}",
                schemaName, dumpsDirectory, ClassName, method);
            TryDeleteFile(tempPath);
            throw;
        }
    }

    /// <summary>
    /// Записывает содержимое дампа во временный файл и возвращает размер.
    /// </summary>
    private async Task<long> WriteDumpFileAsync(
        NpgsqlConnection connection,
        LiveSchema live,
        string tempPath,
        string schemaName,
        string applicationVersion,
        string skeletonSha256Hash,
        DateTime utcCreated,
        CancellationToken cancellationToken)
    {
        await using FileStream stream = new(
            tempPath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize: 81920, useAsync: true);
        await using StreamWriter writer = new(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        await WriteHeaderAsync(writer, live, schemaName, applicationVersion, skeletonSha256Hash, utcCreated).ConfigureAwait(false);

        // Последовательности — до таблиц: DEFAULT nextval(...) разрешается при создании
        foreach (LiveSequence sequence in live.Sequences)
        {
            await writer.WriteLineAsync(BuildCreateSequenceSql(sequence, schemaName)).ConfigureAwait(false);
        }

        await writer.WriteLineAsync();

        // Таблицы со столбцами и ограничениями (кроме внешних ключей)
        foreach (TableDefinition table in live.Tables)
        {
            long rowCount = await CountRowsAsync(connection, schemaName, table.Name, cancellationToken).ConfigureAwait(false);
            await writer.WriteLineAsync($"-- Таблица {SchemaTextNormalizer.QuoteQualifiedName(schemaName, table.Name)}: {rowCount.ToString(System.Globalization.CultureInfo.InvariantCulture)} строк");
            await writer.WriteAsync("CREATE TABLE ");
            await writer.WriteAsync(SchemaTextNormalizer.QuoteQualifiedName(schemaName, table.Name));
            await writer.WriteAsync(BuildTableColumnsAndNonFkConstraints(table));
            await writer.WriteLineAsync(";");
        }

        await writer.WriteLineAsync();

        // Данные таблиц: COPY TO STDOUT → блоки COPY FROM STDIN (текстовый формат PostgreSQL)
        foreach (TableDefinition table in live.Tables)
        {
            string columnList = string.Join(", ", table.Columns
                .Select(column => SchemaTextNormalizer.QuoteIdentifier(column.Name)));
            string qualifiedName = SchemaTextNormalizer.QuoteQualifiedName(schemaName, table.Name);

            await writer.WriteAsync("COPY ");
            await writer.WriteAsync(qualifiedName);
            await writer.WriteAsync(" (");
            await writer.WriteAsync(columnList);
            await writer.WriteLineAsync(") FROM STDIN;");
            await writer.FlushAsync(cancellationToken).ConfigureAwait(false);

            // Текстовый поток COPY читается и переносится в файл порциями;
            // блок using обязателен: завершение COPY происходит при Dispose читателя
            using TextReader copyReader = await connection
                .BeginTextExportAsync($"COPY {qualifiedName} ({columnList}) TO STDOUT", cancellationToken)
                .ConfigureAwait(false);

            char[] buffer = new char[81920];

            while (await copyReader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false) is int read and > 0)
            {
                await writer.WriteAsync(buffer, 0, read).ConfigureAwait(false);
            }

            await writer.WriteLineAsync("\\.");
            await writer.WriteLineAsync();
        }

        // Владение последовательностями (serial-столбцы)
        foreach (LiveSequence sequence in live.Sequences)
        {
            if (sequence.OwnedByTableName is not null && sequence.OwnedByColumnName is not null)
            {
                await writer.WriteAsync("ALTER SEQUENCE ");
                await writer.WriteAsync(SchemaTextNormalizer.QuoteQualifiedName(schemaName, sequence.Name));
                await writer.WriteAsync(" OWNED BY ");
                await writer.WriteAsync(SchemaTextNormalizer.QuoteQualifiedName(schemaName, sequence.OwnedByTableName));
                await writer.WriteAsync('.');
                await writer.WriteAsync(SchemaTextNormalizer.QuoteIdentifier(sequence.OwnedByColumnName));
                await writer.WriteLineAsync(";");
            }
        }

        await writer.WriteLineAsync();

        // Внешние ключи — после загрузки данных
        foreach (TableDefinition table in live.Tables)
        {
            foreach (ConstraintDefinition constraint in table.Constraints.Where(
                         constraint => constraint.Kind is SchemaConstraintKind.ForeignKey))
            {
                await writer.WriteAsync("ALTER TABLE ");
                await writer.WriteAsync(SchemaTextNormalizer.QuoteQualifiedName(schemaName, table.Name));
                await writer.WriteAsync(" ADD CONSTRAINT ");
                await writer.WriteAsync(SchemaTextNormalizer.QuoteIdentifier(constraint.Name));
                await writer.WriteAsync(' ');
                await writer.WriteAsync(constraint.SourceDefinition);
                await writer.WriteLineAsync(";");
            }
        }

        await writer.WriteLineAsync();

        // Индексы — полными операторами pg_get_indexdef
        foreach (IndexDefinition index in live.Indexes)
        {
            await writer.WriteLineAsync(index.SourceDefinition + ";");
        }

        await writer.WriteLineAsync();
        await writer.WriteLineAsync("COMMIT;");
        await writer.WriteLineAsync("-- Конец дампа WebShelf");

        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);

        return stream.Position;
    }

    /// <summary>
    /// Записывает заголовок дампа: метаданные и начало транзакции восстановления.
    /// </summary>
    private async Task WriteHeaderAsync(
        StreamWriter writer,
        LiveSchema live,
        string schemaName,
        string applicationVersion,
        string skeletonSha256Hash,
        DateTime utcCreated)
    {
        await writer.WriteLineAsync("-- Дамп БД WebShelf (структура + данные)");
        await writer.WriteLineAsync("-- Формат: текстовый SQL; восстановление — выполнить скрипт (например, psql)");
        await writer.WriteLineAsync($"-- Версия формата дампа: {DumpFormatVersion}");
        await writer.WriteLineAsync($"-- Время создания (UTC): {utcCreated:yyyy-MM-dd'T'HH:mm:ss.fff'Z'}");
        await writer.WriteLineAsync($"-- Версия приложения: {applicationVersion}");
        await writer.WriteLineAsync($"-- Хеш каркаса (SHA-256): {skeletonSha256Hash}");
        await writer.WriteLineAsync($"-- База данных: {database.DatabaseName}");
        await writer.WriteLineAsync($"-- Хост: {database.Host}, порт: {database.Port}");
        await writer.WriteLineAsync($"-- Схема: {schemaName}");
        await writer.WriteLineAsync($"-- Таблиц: {live.Tables.Count}, последовательностей: {live.Sequences.Count}, индексов: {live.Indexes.Count}");
        await writer.WriteLineAsync("BEGIN;");
        await writer.WriteLineAsync($"SET search_path TO {SchemaTextNormalizer.QuoteIdentifier(schemaName)}, public;");
        await writer.WriteLineAsync("SET client_encoding = 'UTF8';");

        // Схема создаётся явно: дамп обязан восстанавливаться и после DROP SCHEMA
        await writer.WriteLineAsync($"CREATE SCHEMA IF NOT EXISTS {SchemaTextNormalizer.QuoteIdentifier(schemaName)};");
        await writer.WriteLineAsync();
    }

    /// <summary>
    /// Формирует оператор CREATE SEQUENCE с фактическими атрибутами живой последовательности.
    /// </summary>
    private static string BuildCreateSequenceSql(LiveSequence sequence, string schemaName)
    {
        string dataType = sequence.DataType ?? "bigint";
        long maxValue = sequence.MaxValue ?? SequenceTypeMaxValues.GetValueOrDefault(dataType, long.MaxValue);
        long startValue = sequence.StartValue ?? 1;
        long incrementBy = sequence.IncrementBy ?? 1;
        long minValue = sequence.MinValue ?? 1;
        long cacheSize = sequence.CacheSize ?? 1;
        string cycle = sequence.Cycle == true ? " CYCLE" : " NO CYCLE";

        return $"CREATE SEQUENCE {SchemaTextNormalizer.QuoteQualifiedName(schemaName, sequence.Name)} AS {dataType} " +
               $"START WITH {startValue} INCREMENT BY {incrementBy} MINVALUE {minValue} MAXVALUE {maxValue} " +
               $"CACHE {cacheSize}{cycle};";
    }

    /// <summary>
    /// Формирует скобочную часть CREATE TABLE: столбцы и ограничения, кроме внешних ключей.
    /// </summary>
    private static string BuildTableColumnsAndNonFkConstraints(TableDefinition table)
    {
        List<string> members =
        [
            .. table.Columns.Select(column => column.SourceDefinition),
            .. table.Constraints
                .Where(constraint => constraint.Kind is not SchemaConstraintKind.ForeignKey)
                .Select(constraint =>
                    $"CONSTRAINT {SchemaTextNormalizer.QuoteIdentifier(constraint.Name)} {constraint.SourceDefinition}"),
        ];

        return $"({string.Join(", ", members)})";
    }

    /// <summary>
    /// Подсчитывает строки таблицы (метаданные дампа; читается в транзакции снимка).
    /// </summary>
    private static async Task<long> CountRowsAsync(
        NpgsqlConnection connection,
        string schemaName,
        string tableName,
        CancellationToken cancellationToken)
    {
        // Имя таблицы экранируется; значения параметром не выражаются (идентификатор DDL)
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText =
            $"SELECT COUNT(*) FROM {SchemaTextNormalizer.QuoteQualifiedName(schemaName, tableName)}";
        object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return result is long count ? count : 0;
    }

    /// <summary>
    /// Пытается удалить файл, игнорируя ошибки (очистка после сбоя записи дампа).
    /// </summary>
    private static void TryDeleteFile(string path)
    {
        if (path.Length == 0)
        {
            return;
        }

        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex)
        {
            Log.Warning(
                ex,
                "Не удалось удалить незавершённый временный файл дампа. Path={Path}. Class={Class}, Method={Method}",
                path, ClassName, nameof(CreateDumpAsync));
        }
    }
}
