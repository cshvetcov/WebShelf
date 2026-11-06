namespace WebShelf.Classes.DB;

/// <summary>
/// Вид расхождения столбца при сравнении живой схемы с каркасом.
/// </summary>
internal enum ColumnDifferenceKind
{
    /// <summary>Различается тип данных.</summary>
    Type,

    /// <summary>Различается допустимость NULL.</summary>
    Nullability,

    /// <summary>Различается выражение DEFAULT.</summary>
    Default
}

/// <summary>
/// Расхождение столбца, присутствующего и в каркасе, и в живой схеме.
/// </summary>
/// <param name="ColumnName">Имя столбца.</param>
/// <param name="Kind">Вид расхождения.</param>
/// <param name="Expected">Ожидаемое значение (по каркасу).</param>
/// <param name="Actual">Фактическое значение (живая схема).</param>
internal sealed record ColumnDifference(
    string ColumnName,
    ColumnDifferenceKind Kind,
    string Expected,
    string Actual);

/// <summary>
/// Ограничение живой схемы, отсутствующее в каркасе. Для удаления нужны
/// и имя (живое), и таблица — поэтому вынесено в отдельную запись.
/// </summary>
/// <param name="TableName">Таблица, на которой определено ограничение.</param>
/// <param name="Name">Имя ограничения в живой схеме.</param>
/// <param name="Kind">Вид ограничения.</param>
/// <param name="Definition">Нормализованное определение (для журнала).</param>
internal sealed record UnexpectedConstraint(
    string TableName,
    string Name,
    SchemaConstraintKind Kind,
    string Definition);

/// <summary>
/// Расхождения таблицы, присутствующей и в каркасе, и в живой схеме.
/// </summary>
/// <param name="TableName">Имя таблицы.</param>
/// <param name="MissingColumns">Столбцы из каркаса, отсутствующие в живой схеме.</param>
/// <param name="UnexpectedColumns">Столбцы живой схемы, отсутствующие в каркасе.</param>
/// <param name="ChangedColumns">Столбцы с расхождениями атрибутов (тип, NULL, DEFAULT).</param>
/// <param name="MissingConstraints">Ограничения из каркаса, отсутствующие в живой схеме.</param>
/// <param name="UnexpectedConstraints">Ограничения живой схемы, отсутствующие в каркасе.</param>
internal sealed record TableDifference(
    string TableName,
    IReadOnlyList<ColumnDefinition> MissingColumns,
    IReadOnlyList<string> UnexpectedColumns,
    IReadOnlyList<ColumnDifference> ChangedColumns,
    IReadOnlyList<ConstraintDefinition> MissingConstraints,
    IReadOnlyList<UnexpectedConstraint> UnexpectedConstraints);

/// <summary>
/// Расхождение индекса с одинаковым именем в каркасе и живой схеме.
/// </summary>
/// <param name="IndexName">Имя индекса.</param>
/// <param name="Expected">Ожидаемая сигнатура (каркас).</param>
/// <param name="Actual">Фактическая сигнатура (живая схема).</param>
internal sealed record IndexDifference(string IndexName, string Expected, string Actual);

/// <summary>
/// Результат сравнения живой схемы с каркасом: полный перечень расхождений.
/// </summary>
/// <param name="SchemaMissing">Схема отсутствует в базе данных.</param>
/// <param name="MissingTables">Таблицы из каркаса, отсутствующие в живой схеме.</param>
/// <param name="UnexpectedTables">Таблицы живой схемы, отсутствующие в каркасе.</param>
/// <param name="ChangedTables">Таблицы, присутствующие с обеих сторон, но с расхождениями.</param>
/// <param name="MissingSequences">Последовательности из каркаса, отсутствующие в живой схеме.</param>
/// <param name="UnexpectedSequences">Последовательности живой схемы, отсутствующие в каркасе.</param>
/// <param name="MissingIndexes">Индексы из каркаса, отсутствующие в живой схеме.</param>
/// <param name="UnexpectedIndexes">Индексы живой схемы, отсутствующие в каркасе.</param>
/// <param name="ChangedIndexes">Индексы с одинаковым именем, но различающейся сигнатурой.</param>
/// <param name="UnsupportedObjectCount">Количество неподдерживаемых объектов живой схемы.</param>
internal sealed record SchemaDiff(
    bool SchemaMissing,
    IReadOnlyList<TableDefinition> MissingTables,
    IReadOnlyList<string> UnexpectedTables,
    IReadOnlyList<TableDifference> ChangedTables,
    IReadOnlyList<SequenceDefinition> MissingSequences,
    IReadOnlyList<string> UnexpectedSequences,
    IReadOnlyList<IndexDefinition> MissingIndexes,
    IReadOnlyList<string> UnexpectedIndexes,
    IReadOnlyList<IndexDifference> ChangedIndexes,
    int UnsupportedObjectCount)
{
    /// <summary>
    /// Признак полного отсутствия расхождений (включая отсутствие схемы).
    /// </summary>
    internal bool IsEmpty =>
        !SchemaMissing &&
        MissingTables.Count == 0 &&
        UnexpectedTables.Count == 0 &&
        ChangedTables.Count == 0 &&
        MissingSequences.Count == 0 &&
        UnexpectedSequences.Count == 0 &&
        MissingIndexes.Count == 0 &&
        UnexpectedIndexes.Count == 0 &&
        ChangedIndexes.Count == 0 &&
        UnsupportedObjectCount == 0;

    /// <summary>
    /// Признак того, что все расхождения исчерпываются несовпадением типов данных
    /// столбцов, присутствующих с обеих сторон. Обновление структуры (Structure Update)
    /// сознательно не меняет типы существующих столбцов (v1), поэтому такие остаточные
    /// расхождения допускаются контрольной проверкой после применения.
    /// </summary>
    internal bool OnlyColumnTypeDifferences
    {
        get
        {
            // Пустой diff и отсутствие изменённых таблиц — не «расхождение типов»:
            // свойство означает, что расхождения ЕСТЬ и исчерпываются типами столбцов
            if (IsEmpty || ChangedTables.Count == 0)
            {
                return false;
            }

            if (SchemaMissing ||
                MissingTables.Count > 0 ||
                UnexpectedTables.Count > 0 ||
                MissingSequences.Count > 0 ||
                UnexpectedSequences.Count > 0 ||
                MissingIndexes.Count > 0 ||
                UnexpectedIndexes.Count > 0 ||
                ChangedIndexes.Count > 0 ||
                UnsupportedObjectCount > 0)
            {
                return false;
            }

            foreach (TableDifference table in ChangedTables)
            {
                if (table.MissingColumns.Count > 0 ||
                    table.UnexpectedColumns.Count > 0 ||
                    table.MissingConstraints.Count > 0 ||
                    table.UnexpectedConstraints.Count > 0)
                {
                    return false;
                }

                foreach (ColumnDifference column in table.ChangedColumns)
                {
                    if (column.Kind is not ColumnDifferenceKind.Type)
                    {
                        return false;
                    }
                }
            }

            return true;
        }
    }

    /// <summary>
    /// Краткая сводка расхождений для журнала.
    /// </summary>
    /// <returns>Компактная строка вида «таблицы -1/+1; столбцы ~2 …».</returns>
    internal string BuildSummary()
    {
        int changedColumns = 0;
        int missingColumns = 0;
        int unexpectedColumns = 0;
        int missingConstraints = 0;
        int unexpectedConstraints = 0;

        foreach (TableDifference table in ChangedTables)
        {
            changedColumns += table.ChangedColumns.Count;
            missingColumns += table.MissingColumns.Count;
            unexpectedColumns += table.UnexpectedColumns.Count;
            missingConstraints += table.MissingConstraints.Count;
            unexpectedConstraints += table.UnexpectedConstraints.Count;
        }

        List<string> parts = [];

        if (SchemaMissing)
        {
            parts.Add("схема отсутствует");
        }

        parts.Add($"таблицы -{MissingTables.Count}/+{UnexpectedTables.Count}/~{ChangedTables.Count}");
        parts.Add($"столбцы -{missingColumns}/+{unexpectedColumns}/~{changedColumns}");
        parts.Add($"ограничения -{missingConstraints}/+{unexpectedConstraints}");
        parts.Add($"последовательности -{MissingSequences.Count}/+{UnexpectedSequences.Count}");
        parts.Add($"индексы -{MissingIndexes.Count}/+{UnexpectedIndexes.Count}/~{ChangedIndexes.Count}");

        if (UnsupportedObjectCount > 0)
        {
            parts.Add($"неподдерживаемые объекты {UnsupportedObjectCount}");
        }

        return string.Join("; ", parts);
    }
}

/// <summary>
/// Итог сравнения живой схемы с каркасом.
/// </summary>
/// <param name="Matches">Признак полного совпадения структуры с каркасом.</param>
/// <param name="Diff">Перечень расхождений (пуст, если <paramref name="Matches"/>).</param>
internal sealed record SchemaComparison(bool Matches, SchemaDiff Diff);
