using Npgsql;

namespace WebShelf.Classes.DB;

/// <summary>
/// Применение файла-каркаса к базе данных: полный сброс (Full Reset) и
/// обновление структуры (Structure Update).
/// </summary>
/// <remarks>
/// <para><b>Full Reset</b>: <c>DROP SCHEMA … CASCADE</c> → <c>CREATE SCHEMA</c> →
/// выполнение DDL каркаса. Все данные удаляются; путь основной автоматики для
/// пустой схемы и явного программного сброса.</para>
/// <para><b>Structure Update</b> (best-effort, данные сохраняются по возможности):
/// добавление отсутствующих таблиц, столбцов, ограничений, индексов и
/// последовательностей; каскадное удаление объектов, отсутствующих в каркасе.
/// Типы данных существующих столбцов не меняются автоматически (v1) — изменение
/// типа может молча преобразовать данные (например, усечь дробную часть), что
/// запрещено правилом «без потери данных вне явного drop». Изменения
/// nullability и DEFAULT применяются: они либо безопасны, либо завершаются
/// ошибкой PostgreSQL и откатом всей транзакции.</para>
/// <para>Оба режима выполняются в одной транзакции с <c>SET LOCAL search_path</c>,
/// поэтому каркас может использовать как явную квалификацию схемой, так и её
/// отсутствие. Применяемый SQL обязан быть успешно разобран парсером каркаса
/// до вызова — оркестратор гарантирует это. Идентификаторы в генерируемых
/// операторах экранируются; значения параметрами не подставляются (DDL).</para>
/// <para>Каждая операция удаления журналируется отдельным предупреждением (риск R13).</para>
/// </remarks>
internal static class DbSkeletonApplier
{
    private const string ClassName = "WebShelf.Classes.DB.DbSkeletonApplier";

    /// <summary>
    /// Выполняет полный сброс схемы к каркасу: удаление схемы со всеми объектами
    /// (каскадно), повторное создание и применение DDL каркаса.
    /// </summary>
    /// <param name="connection">Открытое соединение PostgreSQL.</param>
    /// <param name="schemaName">Имя схемы.</param>
    /// <param name="skeletonSqlText">Текст SQL-каркаса (должен быть успешно разобран парсером).</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <exception cref="PostgresException">Ошибка выполнения DDL (транзакция откатывается).</exception>
    internal static async Task ApplyFullResetAsync(
        NpgsqlConnection connection,
        string schemaName,
        string skeletonSqlText,
        CancellationToken cancellationToken)
    {
        const string method = nameof(ApplyFullResetAsync);

        ArgumentNullException.ThrowIfNull(connection);
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaName);
        ArgumentException.ThrowIfNullOrWhiteSpace(skeletonSqlText);

        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            await ExecuteAsync(connection, transaction, BuildSetSearchPathSql(schemaName), cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, transaction, $"DROP SCHEMA IF EXISTS {SchemaTextNormalizer.QuoteIdentifier(schemaName)} CASCADE", cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, transaction, $"CREATE SCHEMA {SchemaTextNormalizer.QuoteIdentifier(schemaName)}", cancellationToken).ConfigureAwait(false);
            // Каркас — доверенный файл поставки приложения; выполняется как скрипт
            await ExecuteAsync(connection, transaction, skeletonSqlText, cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await TryRollbackAsync(transaction).ConfigureAwait(false);
            throw;
        }

        Log.Warning(
            "Полный сброс схемы выполнен (DROP SCHEMA CASCADE + каркас). Schema={Schema}. Class={Class}, Method={Method}",
            schemaName, ClassName, method);
    }

    /// <summary>
    /// Приводит живую схему к каркасу с сохранением данных по возможности
    /// (Structure Update, best-effort): создание отсутствующих объектов, удаление
    /// лишних (каскадно), выравнивание nullability/DEFAULT существующих столбцов.
    /// </summary>
    /// <param name="connection">Открытое соединение PostgreSQL.</param>
    /// <param name="schemaName">Имя схемы.</param>
    /// <param name="expected">Манифест ожидаемой структуры (каркас).</param>
    /// <param name="diff">Расхождения живой схемы с каркасом (результат сравнения).</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <exception cref="InvalidOperationException">Передан diff с отсутствующей схемой.</exception>
    /// <exception cref="PostgresException">Ошибка выполнения DDL (транзакция откатывается).</exception>
    internal static async Task ApplyStructureUpdateAsync(
        NpgsqlConnection connection,
        string schemaName,
        SchemaManifest expected,
        SchemaDiff diff,
        CancellationToken cancellationToken)
    {
        const string method = nameof(ApplyStructureUpdateAsync);

        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(diff);
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaName);

        if (diff.SchemaMissing)
        {
            throw new InvalidOperationException(
                "Обновление структуры не выполняется для отсутствующей схемы — используйте применение каркаса.");
        }

        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            await ExecuteAsync(connection, transaction, BuildSetSearchPathSql(schemaName), cancellationToken).ConfigureAwait(false);

            await DropUnexpectedForeignKeysAsync(connection, transaction, diff, schemaName, cancellationToken).ConfigureAwait(false);
            await DropUnexpectedConstraintsAsync(connection, transaction, diff, schemaName, cancellationToken).ConfigureAwait(false);
            await DropIndexesAsync(connection, transaction, diff, schemaName, cancellationToken).ConfigureAwait(false);
            await DropUnexpectedTablesAsync(connection, transaction, diff, schemaName, cancellationToken).ConfigureAwait(false);
            await DropUnexpectedSequencesAsync(connection, transaction, diff, schemaName, cancellationToken).ConfigureAwait(false);
            await DropUnexpectedColumnsAsync(connection, transaction, diff, schemaName, cancellationToken).ConfigureAwait(false);
            await ApplyColumnAttributeChangesAsync(connection, transaction, diff, schemaName, expected, cancellationToken).ConfigureAwait(false);
            await CreateMissingSequencesAsync(connection, transaction, diff, schemaName, cancellationToken).ConfigureAwait(false);
            await CreateMissingTablesAsync(connection, transaction, diff, schemaName, cancellationToken).ConfigureAwait(false);
            await AddMissingColumnsAsync(connection, transaction, diff, schemaName, cancellationToken).ConfigureAwait(false);
            await AddMissingConstraintsAsync(connection, transaction, diff, schemaName, SchemaConstraintKind.ForeignKey, cancellationToken).ConfigureAwait(false);
            await AddMissingConstraintsAsync(connection, transaction, diff, schemaName, null, cancellationToken).ConfigureAwait(false);
            await CreateMissingIndexesAsync(connection, transaction, diff, expected, cancellationToken).ConfigureAwait(false);

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await TryRollbackAsync(transaction).ConfigureAwait(false);
            throw;
        }

        Log.Warning(
            "Обновление структуры схемы выполнено (best-effort, данные сохранены по возможности). Schema={Schema}, Diff={DiffSummary}. Class={Class}, Method={Method}",
            schemaName, diff.BuildSummary(), ClassName, method);
    }

    /// <summary>Удаляет неожиданные внешние ключи (в первую очередь — они ссылаются на изменяемые объекты).</summary>
    private static async Task DropUnexpectedForeignKeysAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        string schemaName,
        CancellationToken cancellationToken)
    {
        foreach (TableDifference table in diff.ChangedTables)
        {
            foreach (UnexpectedConstraint constraint in table.UnexpectedConstraints.Where(
                         constraint => constraint.Kind is SchemaConstraintKind.ForeignKey))
            {
                await DropConstraintAsync(connection, transaction, schemaName, table.TableName, constraint.Name, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Удаляет неожиданные ограничения (кроме внешних ключей, удалённых ранее).</summary>
    private static async Task DropUnexpectedConstraintsAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        string schemaName,
        CancellationToken cancellationToken)
    {
        foreach (TableDifference table in diff.ChangedTables)
        {
            foreach (UnexpectedConstraint constraint in table.UnexpectedConstraints.Where(
                         constraint => constraint.Kind is not SchemaConstraintKind.ForeignKey))
            {
                await DropConstraintAsync(connection, transaction, schemaName, table.TableName, constraint.Name, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Удаляет неожиданные и изменённые индексы (изменённые пересоздаются из каркаса).</summary>
    private static async Task DropIndexesAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        string schemaName,
        CancellationToken cancellationToken)
    {
        List<string> indexNames =
        [
            .. diff.UnexpectedIndexes,
            .. diff.ChangedIndexes.Select(difference => difference.IndexName),
        ];

        foreach (string indexName in indexNames)
        {
            string sql = $"DROP INDEX IF EXISTS {SchemaTextNormalizer.QuoteQualifiedName(schemaName, indexName)} CASCADE";
            LogDrop(sql, schemaName);
            await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Удаляет таблицы, отсутствующие в каркасе (каскадно).</summary>
    private static async Task DropUnexpectedTablesAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        string schemaName,
        CancellationToken cancellationToken)
    {
        foreach (string tableName in diff.UnexpectedTables)
        {
            string sql = $"DROP TABLE IF EXISTS {SchemaTextNormalizer.QuoteQualifiedName(schemaName, tableName)} CASCADE";
            LogDrop(sql, schemaName);
            await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Удаляет последовательности, отсутствующие в каркасе (каскадно).</summary>
    private static async Task DropUnexpectedSequencesAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        string schemaName,
        CancellationToken cancellationToken)
    {
        foreach (string sequenceName in diff.UnexpectedSequences)
        {
            string sql = $"DROP SEQUENCE IF EXISTS {SchemaTextNormalizer.QuoteQualifiedName(schemaName, sequenceName)} CASCADE";
            LogDrop(sql, schemaName);
            await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Удаляет столбцы, отсутствующие в каркасе (каскадно: индексы и ограничения столбца удаляются вместе с ним).</summary>
    private static async Task DropUnexpectedColumnsAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        string schemaName,
        CancellationToken cancellationToken)
    {
        foreach (TableDifference table in diff.ChangedTables)
        {
            foreach (string columnName in table.UnexpectedColumns)
            {
                string sql = $"ALTER TABLE {SchemaTextNormalizer.QuoteQualifiedName(schemaName, table.TableName)} " +
                             $"DROP COLUMN IF EXISTS {SchemaTextNormalizer.QuoteIdentifier(columnName)} CASCADE";
                LogDrop(sql, schemaName);
                await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Выравнивает nullability и DEFAULT существующих столбцов. Типы не меняются (v1) —
    /// фиксируется предупреждением.
    /// </summary>
    private static async Task ApplyColumnAttributeChangesAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        string schemaName,
        SchemaManifest expected,
        CancellationToken cancellationToken)
    {
        const string method = nameof(ApplyColumnAttributeChangesAsync);

        foreach (TableDifference table in diff.ChangedTables)
        {
            foreach (ColumnDifference column in table.ChangedColumns)
            {
                string qualifiedTable = SchemaTextNormalizer.QuoteQualifiedName(schemaName, table.TableName);
                string quotedColumn = SchemaTextNormalizer.QuoteIdentifier(column.ColumnName);

                switch (column.Kind)
                {
                    case ColumnDifferenceKind.Nullability:
                    {
                        string action = column.Expected == "NOT NULL" ? "SET NOT NULL" : "DROP NOT NULL";
                        string sql = $"ALTER TABLE {qualifiedTable} ALTER COLUMN {quotedColumn} {action}";
                        LogDrop(sql, schemaName);
                        await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    case ColumnDifferenceKind.Default:
                    {
                        string? expectedDefault = FindExpectedColumn(expected, table.TableName, column.ColumnName)?.DefaultExpression;
                        string action = expectedDefault is null ? "DROP DEFAULT" : $"SET DEFAULT {expectedDefault}";
                        string sql = $"ALTER TABLE {qualifiedTable} ALTER COLUMN {quotedColumn} {action}";
                        await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
                        break;
                    }

                    case ColumnDifferenceKind.Type:
                    {
                        // Изменение типа не применяется автоматически: ALTER TYPE может молча
                        // преобразовать данные (например, округлить numeric → integer)
                        Log.Warning(
                            "Тип столбца отличается от каркаса и не изменяется автоматически. Schema={Schema}, Table={Table}, Column={Column}, Expected={Expected}, Actual={Actual}. Class={Class}, Method={Method}",
                            schemaName, table.TableName, column.ColumnName, column.Expected, column.Actual, ClassName, method);
                        break;
                    }
                }
            }
        }
    }

    /// <summary>Создаёт отсутствующие последовательности из каркаса.</summary>
    private static async Task CreateMissingSequencesAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        string schemaName,
        CancellationToken cancellationToken)
    {
        foreach (SequenceDefinition sequence in diff.MissingSequences)
        {
            string options = sequence.SourceDefinition.Trim();
            string sql = $"CREATE SEQUENCE {SchemaTextNormalizer.QuoteQualifiedName(schemaName, sequence.Name)}" +
                         (options.Length > 0 ? " " + options : string.Empty);
            await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Создаёт отсутствующие таблицы целиком (столбцы и ограничения из исходного текста каркаса).</summary>
    private static async Task CreateMissingTablesAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        string schemaName,
        CancellationToken cancellationToken)
    {
        foreach (TableDefinition table in diff.MissingTables)
        {
            string sql = $"CREATE TABLE {SchemaTextNormalizer.QuoteQualifiedName(schemaName, table.Name)} {table.SourceDefinition}";
            await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Добавляет отсутствующие столбцы в существующие таблицы.</summary>
    private static async Task AddMissingColumnsAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        string schemaName,
        CancellationToken cancellationToken)
    {
        foreach (TableDifference table in diff.ChangedTables)
        {
            foreach (ColumnDefinition column in table.MissingColumns)
            {
                string sql = $"ALTER TABLE {SchemaTextNormalizer.QuoteQualifiedName(schemaName, table.TableName)} " +
                             $"ADD COLUMN {column.SourceDefinition}";
                await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>Добавляет отсутствующие ограничения. Внешние ключи — последними, прочие — до них.</summary>
    private static async Task AddMissingConstraintsAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        string schemaName,
        SchemaConstraintKind? kindFilter,
        CancellationToken cancellationToken)
    {
        List<(string TableName, ConstraintDefinition Constraint)> additions =
        [
            .. diff.ChangedTables.SelectMany(table => table.MissingConstraints
                .Where(constraint => kindFilter is null || constraint.Kind == kindFilter)
                .Select(constraint => (table.TableName, constraint))),
        ];

        foreach ((string tableName, ConstraintDefinition constraint) in additions)
        {
            string sql = $"ALTER TABLE {SchemaTextNormalizer.QuoteQualifiedName(schemaName, tableName)} " +
                         $"ADD CONSTRAINT {SchemaTextNormalizer.QuoteIdentifier(constraint.Name)} {constraint.SourceDefinition}";
            await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Создаёт отсутствующие и пересоздаёт изменённые индексы операторами каркаса.</summary>
    private static async Task CreateMissingIndexesAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        SchemaDiff diff,
        SchemaManifest expected,
        CancellationToken cancellationToken)
    {
        List<IndexDefinition> indexes =
        [
            .. diff.MissingIndexes,
            .. diff.ChangedIndexes
                .Select(difference => expected.Indexes.FirstOrDefault(
                    index => string.Equals(index.Name, difference.IndexName, StringComparison.OrdinalIgnoreCase)))
                .OfType<IndexDefinition>(),
        ];

        foreach (IndexDefinition index in indexes)
        {
            await ExecuteAsync(connection, transaction, index.SourceDefinition, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Удаляет ограничение таблицы.</summary>
    private static async Task DropConstraintAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string schemaName,
        string tableName,
        string constraintName,
        CancellationToken cancellationToken)
    {
        string sql = $"ALTER TABLE {SchemaTextNormalizer.QuoteQualifiedName(schemaName, tableName)} " +
                     $"DROP CONSTRAINT IF EXISTS {SchemaTextNormalizer.QuoteIdentifier(constraintName)}";
        LogDrop(sql, schemaName);
        await ExecuteAsync(connection, transaction, sql, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Формирует установку search_path на время транзакции (каркас может не квалифицировать имена).</summary>
    private static string BuildSetSearchPathSql(string schemaName)
    {
        return $"SET LOCAL search_path TO {SchemaTextNormalizer.QuoteIdentifier(schemaName)}, public";
    }

    /// <summary>Ищет ожидаемый столбец в манифесте каркаса (для SET DEFAULT).</summary>
    private static ColumnDefinition? FindExpectedColumn(SchemaManifest expected, string tableName, string columnName)
    {
        TableDefinition? table = expected.Tables.FirstOrDefault(
            candidate => string.Equals(candidate.Name, tableName, StringComparison.OrdinalIgnoreCase));

        return table?.Columns.FirstOrDefault(
            column => string.Equals(column.Name, columnName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Выполняет SQL-оператор в транзакции.</summary>
    private static async Task ExecuteAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string sql,
        CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Журналирует деструктивную операцию (риск R13 — каждая DROP-операция отдельно).</summary>
    private static void LogDrop(string sql, string schemaName)
    {
        const string method = nameof(LogDrop);

        Log.Warning(
            "Применяется деструктивная операция (возможно каскадное удаление зависимостей). Schema={Schema}, Sql={Sql}. Class={Class}, Method={Method}",
            schemaName, sql, ClassName, method);
    }

    /// <summary>Пытается откатить транзакцию, проглатывая ошибки отката (основная исключение пробрасывается).</summary>
    private static async Task TryRollbackAsync(NpgsqlTransaction transaction)
    {
        try
        {
            await transaction.RollbackAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log.Warning(
                ex,
                "Не удалось откатить транзакцию изменения схемы (соединение будет закрыто). Class={Class}, Method={Method}",
                ClassName, nameof(TryRollbackAsync));
        }
    }
}
