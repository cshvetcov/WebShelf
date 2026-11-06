namespace WebShelf.Classes.DB;

/// <summary>
/// Сравнение ожидаемой структуры (манифест из файла-каркаса) с фактической
/// структурой живой схемы: таблицы, столбцы (имя, тип, nullability, default),
/// ограничения PK/FK/UNIQUE/CHECK, последовательности и отдельные индексы.
/// </summary>
/// <remarks>
/// Ограничения сравниваются по паре (вид, нормализованное определение), а не по имени:
/// имя, которое генерирует PostgreSQL для inline-объявлений, не обязано совпадать
/// с именем в каркасе. Последовательности сравниваются по наличию (имени) —
/// атрибуты последовательностей относятся к данным и меняются в ходе работы.
/// </remarks>
internal static class SchemaComparer
{
    /// <summary>
    /// Сравнивает манифест каркаса с живой схемой.
    /// </summary>
    /// <param name="expected">Ожидаемая структура (каркас).</param>
    /// <param name="actual">Фактическая структура (живая схема).</param>
    /// <returns>Результат сравнения с полным перечнем расхождений.</returns>
    /// <exception cref="ArgumentNullException">Аргумент равен <see langword="null"/>.</exception>
    internal static SchemaComparison Compare(SchemaManifest expected, LiveSchema actual)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(actual);

        List<TableDefinition> missingTables = [];
        List<string> unexpectedTables = [];
        List<TableDifference> changedTables = [];

        Dictionary<string, TableDefinition> expectedTables = expected.Tables.ToDictionary(
            table => table.Name, table => table, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, TableDefinition> actualTables = actual.Tables.ToDictionary(
            table => table.Name, table => table, StringComparer.OrdinalIgnoreCase);

        foreach ((string tableName, TableDefinition expectedTable) in expectedTables)
        {
            if (!actualTables.TryGetValue(tableName, out TableDefinition? liveTable))
            {
                missingTables.Add(expectedTable);
                continue;
            }

            TableDifference? difference = CompareTable(expectedTable, liveTable, expected.SchemaName);

            if (difference is not null)
            {
                changedTables.Add(difference);
            }
        }

        foreach (string liveTableName in actualTables.Keys)
        {
            if (!expectedTables.ContainsKey(liveTableName))
            {
                unexpectedTables.Add(liveTableName);
            }
        }

        List<SequenceDefinition> missingSequences =
        [
            .. expected.Sequences.Where(sequence => !actual.Sequences.Any(live =>
                string.Equals(live.Name, sequence.Name, StringComparison.OrdinalIgnoreCase))),
        ];

        List<string> unexpectedSequences =
        [
            .. actual.Sequences
                .Where(live => !expected.Sequences.Any(sequence =>
                    string.Equals(live.Name, sequence.Name, StringComparison.OrdinalIgnoreCase)))
                .Select(live => live.Name),
        ];

        Dictionary<string, IndexDefinition> expectedIndexes = expected.Indexes.ToDictionary(
            index => index.Name, index => index, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, IndexDefinition> actualIndexes = actual.Indexes.ToDictionary(
            index => index.Name, index => index, StringComparer.OrdinalIgnoreCase);

        List<IndexDefinition> missingIndexes = [];
        List<string> unexpectedIndexes = [];
        List<IndexDifference> changedIndexes = [];

        foreach ((string indexName, IndexDefinition expectedIndex) in expectedIndexes)
        {
            if (!actualIndexes.TryGetValue(indexName, out IndexDefinition? liveIndex))
            {
                missingIndexes.Add(expectedIndex);
            }
            else if (!string.Equals(expectedIndex.Definition, liveIndex.Definition, StringComparison.Ordinal))
            {
                changedIndexes.Add(new IndexDifference(indexName, expectedIndex.Definition, liveIndex.Definition));
            }
        }

        foreach (string liveIndexName in actualIndexes.Keys)
        {
            if (!expectedIndexes.ContainsKey(liveIndexName))
            {
                unexpectedIndexes.Add(liveIndexName);
            }
        }

        SchemaDiff diff = new(
            SchemaMissing: !actual.SchemaExists,
            missingTables,
            unexpectedTables,
            changedTables,
            missingSequences,
            unexpectedSequences,
            missingIndexes,
            unexpectedIndexes,
            changedIndexes,
            actual.UnsupportedObjectCount);

        return new SchemaComparison(diff.IsEmpty, diff);
    }

    /// <summary>
    /// Сравнивает таблицу, присутствующую и в каркасе, и в живой схеме.
    /// </summary>
    /// <returns>Расхождения таблицы или <see langword="null"/>, если таблицы совпадают.</returns>
    private static TableDifference? CompareTable(TableDefinition expectedTable, TableDefinition liveTable, string schemaName)
    {
        List<ColumnDefinition> missingColumns = [];
        List<string> unexpectedColumns = [];
        List<ColumnDifference> changedColumns = [];

        Dictionary<string, ColumnDefinition> expectedColumns = expectedTable.Columns.ToDictionary(
            column => column.Name, column => column, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, ColumnDefinition> actualColumns = liveTable.Columns.ToDictionary(
            column => column.Name, column => column, StringComparer.OrdinalIgnoreCase);

        foreach ((string columnName, ColumnDefinition expectedColumn) in expectedColumns)
        {
            if (!actualColumns.TryGetValue(columnName, out ColumnDefinition? liveColumn))
            {
                missingColumns.Add(expectedColumn);
                continue;
            }

            string expectedType = SchemaTextNormalizer.NormalizeType(expectedColumn.TypeName);
            string actualType = SchemaTextNormalizer.NormalizeType(liveColumn.TypeName);

            if (!string.Equals(expectedType, actualType, StringComparison.Ordinal))
            {
                changedColumns.Add(new ColumnDifference(
                    columnName, ColumnDifferenceKind.Type, expectedType, actualType));
            }

            if (expectedColumn.IsNullable != liveColumn.IsNullable)
            {
                changedColumns.Add(new ColumnDifference(
                    columnName,
                    ColumnDifferenceKind.Nullability,
                    expectedColumn.IsNullable ? "NULL" : "NOT NULL",
                    liveColumn.IsNullable ? "NULL" : "NOT NULL"));
            }

            string? expectedDefault = SchemaTextNormalizer.NormalizeDefaultExpression(expectedColumn.DefaultExpression, schemaName);
            string? actualDefault = SchemaTextNormalizer.NormalizeDefaultExpression(liveColumn.DefaultExpression, schemaName);

            if (!string.Equals(expectedDefault, actualDefault, StringComparison.Ordinal))
            {
                changedColumns.Add(new ColumnDifference(
                    columnName,
                    ColumnDifferenceKind.Default,
                    expectedDefault ?? "(нет)",
                    actualDefault ?? "(нет)"));
            }
        }

        foreach (string liveColumnName in actualColumns.Keys)
        {
            if (!expectedColumns.ContainsKey(liveColumnName))
            {
                unexpectedColumns.Add(liveColumnName);
            }
        }

        List<ConstraintDefinition> missingConstraints = [];
        List<UnexpectedConstraint> unexpectedConstraints = [];

        HashSet<string> liveSignatures = liveTable.Constraints
            .Select(constraint => BuildConstraintSignature(constraint.Kind, constraint.Definition))
            .ToHashSet(StringComparer.Ordinal);

        HashSet<string> expectedSignatures = expectedTable.Constraints
            .Select(constraint => BuildConstraintSignature(constraint.Kind, constraint.Definition))
            .ToHashSet(StringComparer.Ordinal);

        foreach (ConstraintDefinition expectedConstraint in expectedTable.Constraints)
        {
            string signature = BuildConstraintSignature(expectedConstraint.Kind, expectedConstraint.Definition);

            if (!liveSignatures.Contains(signature))
            {
                missingConstraints.Add(expectedConstraint);
            }
        }

        foreach (ConstraintDefinition liveConstraint in liveTable.Constraints)
        {
            string signature = BuildConstraintSignature(liveConstraint.Kind, liveConstraint.Definition);

            if (!expectedSignatures.Contains(signature))
            {
                unexpectedConstraints.Add(new UnexpectedConstraint(
                    liveTable.Name,
                    liveConstraint.Name,
                    liveConstraint.Kind,
                    liveConstraint.Definition));
            }
        }

        if (missingColumns.Count == 0 &&
            unexpectedColumns.Count == 0 &&
            changedColumns.Count == 0 &&
            missingConstraints.Count == 0 &&
            unexpectedConstraints.Count == 0)
        {
            return null;
        }

        return new TableDifference(
            expectedTable.Name,
            missingColumns,
            unexpectedColumns,
            changedColumns,
            missingConstraints,
            unexpectedConstraints);
    }

    /// <summary>Сигнатура ограничения для сопоставления: вид + нормализованное определение.</summary>
    private static string BuildConstraintSignature(SchemaConstraintKind kind, string definition)
    {
        return $"{kind}|{definition}";
    }
}
