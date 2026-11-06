using Npgsql;

namespace WebShelf.Classes.DB;

/// <summary>
/// Чтение фактической структуры схемы из каталогов PostgreSQL
/// (<c>pg_catalog</c> / <c>information_schema</c>-представления).
/// </summary>
/// <remarks>
/// Область чтения ограничена поддерживаемым набором объектов: таблицы (relkind = r),
/// столбцы, ограничения PK/FK/UNIQUE/CHECK (и подсчёт прочих), последовательности,
/// отдельные индексы. Обнаружение объектов вне набора (представления, функции,
/// триггеры, identity-столбцы и т.п.) увеличивает <see cref="LiveSchema.UnsupportedObjectCount"/> —
/// дамп такие схемы не создаёт, изменения не выполняются (защита от неполного дампа, риск R3).
/// Все запросы параметризованы (<c>@schema</c>), чтение выполняется по одному соединению.
/// </remarks>
internal static class LiveSchemaReader
{
    private const string ClassName = "WebShelf.Classes.DB.LiveSchemaReader";

    /// <summary>
    /// Читает фактическую структуру схемы из каталогов PostgreSQL.
    /// </summary>
    /// <param name="connection">Открытое соединение PostgreSQL.</param>
    /// <param name="schemaName">Имя схемы.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Фактическая структура схемы (включая признаки отсутствия схемы и неподдерживаемых объектов).</returns>
    /// <exception cref="PostgresException">Ошибка выполнения запросов к каталогам.</exception>
    internal static async Task<LiveSchema> ReadAsync(
        NpgsqlConnection connection,
        string schemaName,
        CancellationToken cancellationToken)
    {
        const string method = nameof(ReadAsync);

        ArgumentNullException.ThrowIfNull(connection);
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaName);

        bool schemaExists = await ExecuteScalarAsync<bool>(
            connection,
            "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = @schema)",
            schemaName,
            cancellationToken).ConfigureAwait(false);

        if (!schemaExists)
        {
            Log.Debug(
                "Схема БД отсутствует. Schema={Schema}. Class={Class}, Method={Method}",
                schemaName, ClassName, method);

            return new LiveSchema(schemaName, SchemaExists: false, [], [], [], 0, string.Empty);
        }

        IReadOnlyList<string> tableNames = await ReadTableNamesAsync(connection, schemaName, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ColumnRow> columnRows = await ReadColumnsAsync(connection, schemaName, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ConstraintRow> constraintRows = await ReadConstraintsAsync(connection, schemaName, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<LiveSequence> sequences = await ReadSequencesAsync(connection, schemaName, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<IndexDefinition> indexes = await ReadIndexesAsync(connection, schemaName, cancellationToken).ConfigureAwait(false);
        (int unsupportedCount, string unsupportedSummary) = await ReadUnsupportedObjectCountAsync(connection, schemaName, cancellationToken).ConfigureAwait(false);

        List<TableDefinition> tables = BuildTableDefinitions(tableNames, columnRows, constraintRows, schemaName);

        Log.Debug(
            "Живая схема прочитана. Schema={Schema}, Tables={Tables}, Sequences={Sequences}, Indexes={Indexes}, Unsupported={Unsupported}. Class={Class}, Method={Method}",
            schemaName, tables.Count, sequences.Count, indexes.Count, unsupportedCount, ClassName, method);

        return new LiveSchema(schemaName, SchemaExists: true, tables, sequences, indexes, unsupportedCount, unsupportedSummary);
    }

    /// <summary>Имена таблиц схемы (relkind = r).</summary>
    private static async Task<IReadOnlyList<string>> ReadTableNamesAsync(
        NpgsqlConnection connection,
        string schemaName,
        CancellationToken cancellationToken)
    {
        List<string> tableNames = [];

        await using NpgsqlCommand command = CreateCommand(
            connection,
            """
            SELECT c.relname
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = @schema AND c.relkind = 'r'
            ORDER BY c.relname
            """,
            schemaName);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            tableNames.Add(reader.GetString(0));
        }

        return tableNames;
    }

    /// <summary>Столбцы таблиц схемы.</summary>
    private static async Task<IReadOnlyList<ColumnRow>> ReadColumnsAsync(
        NpgsqlConnection connection,
        string schemaName,
        CancellationToken cancellationToken)
    {
        List<ColumnRow> rows = [];

        await using NpgsqlCommand command = CreateCommand(
            connection,
            """
            SELECT c.relname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull,
                   pg_catalog.pg_get_expr(ad.adbin, ad.adrelid)
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
            WHERE n.nspname = @schema AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
            ORDER BY c.relname, a.attnum
            """,
            schemaName);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(new ColumnRow(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetBoolean(3),
                reader.IsDBNull(4) ? null : reader.GetString(4)));
        }

        return rows;
    }

    /// <summary>Ограничения таблиц схемы.</summary>
    private static async Task<IReadOnlyList<ConstraintRow>> ReadConstraintsAsync(
        NpgsqlConnection connection,
        string schemaName,
        CancellationToken cancellationToken)
    {
        List<ConstraintRow> rows = [];

        await using NpgsqlCommand command = CreateCommand(
            connection,
            """
            SELECT c.relname, con.conname, con.contype::text, pg_catalog.pg_get_constraintdef(con.oid)
            FROM pg_constraint con
            JOIN pg_class c ON c.oid = con.conrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = @schema AND con.contype <> 'n'
            ORDER BY c.relname, con.conname
            """,
            schemaName);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(new ConstraintRow(
                reader.GetString(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3)));
        }

        return rows;
    }

    /// <summary>Последовательности схемы с атрибутами и владением.</summary>
    private static async Task<IReadOnlyList<LiveSequence>> ReadSequencesAsync(
        NpgsqlConnection connection,
        string schemaName,
        CancellationToken cancellationToken)
    {
        Dictionary<string, (string? Table, string? Column)> ownership = await ReadSequenceOwnershipAsync(
            connection, schemaName, cancellationToken).ConfigureAwait(false);

        List<LiveSequence> sequences = [];

        await using NpgsqlCommand command = CreateCommand(
            connection,
            """
            SELECT sequencename, data_type::text, start_value, increment_by, min_value, max_value, cache_size, cycle
            FROM pg_sequences
            WHERE schemaname = @schema
            ORDER BY sequencename
            """,
            schemaName);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            string name = reader.GetString(0);
            (string? ownedByTable, string? ownedByColumn) = ownership.GetValueOrDefault(name);
            string? dataType = reader.IsDBNull(1) ? null : reader.GetString(1);

            sequences.Add(new LiveSequence(
                name,
                dataType,
                reader.IsDBNull(2) ? null : reader.GetInt64(2),
                reader.IsDBNull(3) ? null : reader.GetInt64(3),
                reader.IsDBNull(4) ? null : reader.GetInt64(4),
                reader.IsDBNull(5) ? null : reader.GetInt64(5),
                reader.IsDBNull(6) ? null : reader.GetInt64(6),
                reader.IsDBNull(7) ? null : reader.GetBoolean(7),
                ownedByTable,
                ownedByColumn));
        }

        return sequences;
    }

    /// <summary>Владение последовательностями столбцами (авто-зависимости serial).</summary>
    private static async Task<Dictionary<string, (string? Table, string? Column)>> ReadSequenceOwnershipAsync(
        NpgsqlConnection connection,
        string schemaName,
        CancellationToken cancellationToken)
    {
        Dictionary<string, (string? Table, string? Column)> ownership = new(StringComparer.OrdinalIgnoreCase);

        await using NpgsqlCommand command = CreateCommand(
            connection,
            """
            SELECT s.relname, t.relname, a.attname
            FROM pg_depend d
            JOIN pg_class s ON s.oid = d.objid
            JOIN pg_namespace n ON n.oid = s.relnamespace
            JOIN pg_class t ON t.oid = d.refobjid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = d.refobjsubid
            WHERE d.classid = 'pg_class'::regclass
              AND d.refclassid = 'pg_class'::regclass
              AND d.deptype = 'a'
              AND s.relkind = 'S'
              AND n.nspname = @schema
            """,
            schemaName);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            ownership[reader.GetString(0)] = (reader.GetString(1), reader.GetString(2));
        }

        return ownership;
    }

    /// <summary>Отдельные индексы схемы (не обслуживающие ограничения).</summary>
    private static async Task<IReadOnlyList<IndexDefinition>> ReadIndexesAsync(
        NpgsqlConnection connection,
        string schemaName,
        CancellationToken cancellationToken)
    {
        List<(string Name, string Table, bool IsUnique, string Definition)> rows = [];

        await using NpgsqlCommand command = CreateCommand(
            connection,
            """
            SELECT idxcls.relname, tbl.relname, idx.indisunique, pg_catalog.pg_get_indexdef(idx.indexrelid)
            FROM pg_index idx
            JOIN pg_class idxcls ON idxcls.oid = idx.indexrelid
            JOIN pg_class tbl ON tbl.oid = idx.indrelid
            JOIN pg_namespace n ON n.oid = tbl.relnamespace
            WHERE n.nspname = @schema
              AND NOT EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conindid = idx.indexrelid)
            ORDER BY idxcls.relname
            """,
            schemaName);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add((reader.GetString(0), reader.GetString(1), reader.GetBoolean(2), reader.GetString(3)));
        }

        List<IndexDefinition> indexes =
        [
            .. rows.Select(row => new IndexDefinition(
                row.Name,
                row.Table,
                row.IsUnique,
                BuildIndexSignature(row.Name, row.Table, row.IsUnique, row.Definition, schemaName),
                row.Definition)),
        ];

        return indexes;
    }

    /// <summary>Подсчёт объектов вне поддерживаемого набора (представления, функции, триггеры и т.п.).</summary>
    private static async Task<(int Count, string Summary)> ReadUnsupportedObjectCountAsync(
        NpgsqlConnection connection,
        string schemaName,
        CancellationToken cancellationToken)
    {
        long relations = await ExecuteScalarAsync<long>(
            connection,
            """
            SELECT COUNT(*)
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = @schema AND c.relkind IN ('v', 'm', 'p', 'f')
            """,
            schemaName,
            cancellationToken).ConfigureAwait(false);

        long routines = await ExecuteScalarAsync<long>(
            connection,
            """
            SELECT COUNT(*)
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = @schema
            """,
            schemaName,
            cancellationToken).ConfigureAwait(false);

        long triggers = await ExecuteScalarAsync<long>(
            connection,
            """
            SELECT COUNT(*)
            FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = @schema AND NOT t.tgisinternal
            """,
            schemaName,
            cancellationToken).ConfigureAwait(false);

        long types = await ExecuteScalarAsync<long>(
            connection,
            """
            SELECT COUNT(*)
            FROM pg_type tp
            JOIN pg_namespace n ON n.oid = tp.typnamespace
            LEFT JOIN pg_class rel ON rel.oid = tp.typrelid
            WHERE n.nspname = @schema
              AND (tp.typtype IN ('d', 'e') OR (tp.typtype = 'c' AND rel.relkind = 'c'))
            """,
            schemaName,
            cancellationToken).ConfigureAwait(false);

        long identityColumns = await ExecuteScalarAsync<long>(
            connection,
            """
            SELECT COUNT(*)
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = @schema AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped AND a.attidentity <> ''
            """,
            schemaName,
            cancellationToken).ConfigureAwait(false);

        long extensions = await ExecuteScalarAsync<long>(
            connection,
            """
            SELECT COUNT(*)
            FROM pg_extension e
            JOIN pg_namespace n ON n.oid = e.extnamespace
            WHERE n.nspname = @schema
            """,
            schemaName,
            cancellationToken).ConfigureAwait(false);

        int total = (int)(relations + routines + triggers + types + identityColumns + extensions);

        if (total == 0)
        {
            return (0, string.Empty);
        }

        string summary =
            $"представления/прочие отношения: {relations}; функции и процедуры: {routines}; " +
            $"триггеры: {triggers}; типы (enum/domain/composite): {types}; identity-столбцы: {identityColumns}; расширения: {extensions}";

        return (total, summary);
    }

    /// <summary>Собирает определения таблиц из прочитанных строк каталога.</summary>
    private static List<TableDefinition> BuildTableDefinitions(
        IReadOnlyList<string> tableNames,
        IReadOnlyList<ColumnRow> columnRows,
        IReadOnlyList<ConstraintRow> constraintRows,
        string schemaName)
    {
        List<TableDefinition> tables = [];

        foreach (string tableName in tableNames)
        {
            List<ColumnDefinition> columns =
            [
                .. columnRows
                    .Where(row => string.Equals(row.TableName, tableName, StringComparison.OrdinalIgnoreCase))
                    .Select(row => new ColumnDefinition(
                        row.ColumnName,
                        row.TypeName,
                        !row.IsNotNullable,
                        row.DefaultExpression,
                        BuildColumnSource(row, schemaName))),
            ];

            List<ConstraintDefinition> constraints =
            [
                .. constraintRows
                    .Where(row => string.Equals(row.TableName, tableName, StringComparison.OrdinalIgnoreCase))
                    .Select(row => new ConstraintDefinition(
                        row.ConstraintName,
                        MapConstraintKind(row.ConstraintType),
                        SchemaTextNormalizer.NormalizeDefinitionText(row.Definition, schemaName),
                        row.Definition)),
            ];

            string source = BuildTableSource(columns, constraints);
            tables.Add(new TableDefinition(tableName, columns, constraints, source));
        }

        return tables;
    }

    /// <summary>Формирует текст определения столбца живой схемы (для дампа).</summary>
    private static string BuildColumnSource(ColumnRow row, string schemaName)
    {
        List<string> parts =
        [
            SchemaTextNormalizer.QuoteIdentifier(row.ColumnName),
            row.TypeName,
        ];

        if (row.IsNotNullable)
        {
            parts.Add("NOT NULL");
        }

        if (row.DefaultExpression is not null)
        {
            parts.Add($"DEFAULT {row.DefaultExpression}");
        }

        return string.Join(' ', parts);
    }

    /// <summary>Формирует текст определений таблицы в скобках (для дампа).</summary>
    private static string BuildTableSource(List<ColumnDefinition> columns, List<ConstraintDefinition> constraints)
    {
        List<string> members =
        [
            .. columns.Select(column => column.SourceDefinition),
            .. constraints.Select(constraint =>
                $"CONSTRAINT {SchemaTextNormalizer.QuoteIdentifier(constraint.Name)} {constraint.SourceDefinition}"),
        ];

        return $"({string.Join(", ", members)})";
    }

    /// <summary>Строит сигнатуру индекса живой схемы по тексту pg_get_indexdef.</summary>
    private static string BuildIndexSignature(string name, string table, bool isUnique, string definition, string schemaName)
    {
        string columns = SchemaTextNormalizer.ExtractIndexColumns(definition, schemaName);
        return $"{name}|{table}|{(isUnique ? "unique" : "plain")}|{columns}";
    }

    /// <summary>Сопоставляет код contype из pg_constraint с видом ограничения.</summary>
    /// <remarks>
    /// NOT NULL-ограничения (contype = 'n', PostgreSQL 18+) не учитываются:
    /// допустимость NULL сравнивается как атрибут столбца, а не ограничение.
    /// </remarks>
    private static SchemaConstraintKind MapConstraintKind(string constraintType)
    {
        return constraintType switch
        {
            "p" => SchemaConstraintKind.PrimaryKey,
            "f" => SchemaConstraintKind.ForeignKey,
            "u" => SchemaConstraintKind.Unique,
            "c" => SchemaConstraintKind.Check,
            _ => SchemaConstraintKind.Other,
        };
    }

    /// <summary>Создаёт параметризованную команду к каталогам.</summary>
    private static NpgsqlCommand CreateCommand(NpgsqlConnection connection, string commandText, string schemaName)
    {
        // Команды автоматически участвуют в активной транзакции соединения (Npgsql 6+)
        NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = commandText;
        command.Parameters.AddWithValue("schema", schemaName);
        return command;
    }

    /// <summary>Выполняет скалярный запрос к каталогам (конвертация через IConvertible).</summary>
    private static async Task<T> ExecuteScalarAsync<T>(
        NpgsqlConnection connection,
        string commandText,
        string schemaName,
        CancellationToken cancellationToken) where T : IConvertible
    {
        await using NpgsqlCommand command = CreateCommand(connection, commandText, schemaName);
        object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return (T)Convert.ChangeType(result!, typeof(T), System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>Строка чтения столбцов каталога.</summary>
    private sealed record ColumnRow(
        string TableName,
        string ColumnName,
        string TypeName,
        bool IsNotNullable,
        string? DefaultExpression);

    /// <summary>Строка чтения ограничений каталога.</summary>
    private sealed record ConstraintRow(
        string TableName,
        string ConstraintName,
        string ConstraintType,
        string Definition);
}
