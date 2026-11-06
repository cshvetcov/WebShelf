namespace WebShelf.Classes.DB;

/// <summary>
/// Вид ограничения целостности, поддерживаемый сервисной инфраструктурой схемы БД.
/// </summary>
internal enum SchemaConstraintKind
{
    /// <summary>Первичный ключ (PRIMARY KEY).</summary>
    PrimaryKey,

    /// <summary>Внешний ключ (FOREIGN KEY).</summary>
    ForeignKey,

    /// <summary>Уникальное ограничение (UNIQUE).</summary>
    Unique,

    /// <summary>Проверочное ограничение (CHECK).</summary>
    Check,

    /// <summary>
    /// Ограничение, не входящее в поддерживаемый набор (например, EXCLUDE).
    /// Встречается только в живой схеме: каркас такие ограничения не описывает,
    /// а их наличие трактуется как расхождение.
    /// </summary>
    Other
}

/// <summary>
/// Описание столбца таблицы — из файла-каркаса или из живой схемы.
/// </summary>
/// <param name="Name">Имя столбца.</param>
/// <param name="TypeName">Тип данных (исходный текст; сравнение выполняется после нормализации).</param>
/// <param name="IsNullable">Допустимость <see langword="null"/> в столбце.</param>
/// <param name="DefaultExpression">Выражение DEFAULT; <see langword="null"/>, если значение по умолчанию не задано.</param>
/// <param name="SourceDefinition">Исходный текст определения столбца (контекст <c>ADD COLUMN</c> / <c>CREATE TABLE</c>).</param>
internal sealed record ColumnDefinition(
    string Name,
    string TypeName,
    bool IsNullable,
    string? DefaultExpression,
    string SourceDefinition);

/// <summary>
/// Описание ограничения целостности таблицы — из файла-каркаса или из живой схемы.
/// </summary>
/// <param name="Name">Имя ограничения. Для ограничений, объявленных в каркасе без имени,
/// подставляется имя, которое PostgreSQL сгенерировал бы по умолчанию.</param>
/// <param name="Kind">Вид ограничения.</param>
/// <param name="Definition">Нормализованное определение (тело ограничения) — основа сравнения.</param>
/// <param name="SourceDefinition">Исходный текст определения (контекст <c>ADD CONSTRAINT</c>).</param>
internal sealed record ConstraintDefinition(
    string Name,
    SchemaConstraintKind Kind,
    string Definition,
    string SourceDefinition);

/// <summary>
/// Описание последовательности из файла-каркаса.
/// Сравнение живой схемы с каркасом выполняется по наличию последовательностей (по имени).
/// </summary>
/// <param name="Name">Имя последовательности.</param>
/// <param name="SourceDefinition">Исходный текст опций после имени (контекст <c>CREATE SEQUENCE</c>; может быть пустым).</param>
internal sealed record SequenceDefinition(string Name, string SourceDefinition);

/// <summary>
/// Описание отдельного индекса (не индекса, обслуживающего ограничение) —
/// из файла-каркаса или из живой схемы.
/// </summary>
/// <param name="Name">Имя индекса.</param>
/// <param name="TableName">Имя таблицы, на которой построен индекс.</param>
/// <param name="IsUnique">Признак уникального индекса.</param>
/// <param name="Definition">Нормализованная сигнатура индекса (имя, таблица, уникальность, выражение столбцов).</param>
/// <param name="SourceDefinition">Полный исходный текст оператора <c>CREATE INDEX</c>.</param>
internal sealed record IndexDefinition(
    string Name,
    string TableName,
    bool IsUnique,
    string Definition,
    string SourceDefinition);

/// <summary>
/// Описание таблицы — из файла-каркаса или из живой схемы.
/// </summary>
/// <param name="Name">Имя таблицы.</param>
/// <param name="Columns">Столбцы в порядке объявления.</param>
/// <param name="Constraints">Ограничения таблицы (включая вынесенные в <c>ALTER TABLE … ADD CONSTRAINT</c>).</param>
/// <param name="SourceDefinition">Исходный текст определений таблицы в скобках (контекст <c>CREATE TABLE</c>).</param>
internal sealed record TableDefinition(
    string Name,
    IReadOnlyList<ColumnDefinition> Columns,
    IReadOnlyList<ConstraintDefinition> Constraints,
    string SourceDefinition);

/// <summary>
/// Ожидаемая структура схемы БД, вычисленная из файла-каркаса.
/// Единственный источник истины — SQL-файл: манифест всегда разбирается из него,
/// поэтому расхождение «манифест vs SQL» исключено по построению.
/// </summary>
/// <param name="SchemaName">Имя схемы (<c>webshelf</c> по умолчанию).</param>
/// <param name="Tables">Ожидаемые таблицы.</param>
/// <param name="Sequences">Ожидаемые последовательности.</param>
/// <param name="Indexes">Ожидаемые отдельные индексы.</param>
internal sealed record SchemaManifest(
    string SchemaName,
    IReadOnlyList<TableDefinition> Tables,
    IReadOnlyList<SequenceDefinition> Sequences,
    IReadOnlyList<IndexDefinition> Indexes);

/// <summary>
/// Описание последовательности живой схемы с атрибутами (для дампа).
/// </summary>
/// <param name="Name">Имя последовательности.</param>
/// <param name="DataType">Тип данных последовательности (например, <c>bigint</c>).</param>
/// <param name="StartValue">Начальное значение (START WITH).</param>
/// <param name="IncrementBy">Шаг приращения (INCREMENT BY).</param>
/// <param name="MinValue">Минимальное значение (MINVALUE).</param>
/// <param name="MaxValue">Максимальное значение (MAXVALUE).</param>
/// <param name="CacheSize">Размер кэша (CACHE).</param>
/// <param name="Cycle">Признак цикличности (CYCLE).</param>
/// <param name="OwnedByTableName">Таблица-владелец (для последовательностей столбцов serial); <see langword="null"/>, если владельца нет.</param>
/// <param name="OwnedByColumnName">Столбец-владелец; <see langword="null"/>, если владельца нет.</param>
internal sealed record LiveSequence(
    string Name,
    string? DataType,
    long? StartValue,
    long? IncrementBy,
    long? MinValue,
    long? MaxValue,
    long? CacheSize,
    bool? Cycle,
    string? OwnedByTableName,
    string? OwnedByColumnName);

/// <summary>
/// Фактическая структура схемы БД, прочитанная из каталогов PostgreSQL.
/// </summary>
/// <param name="SchemaName">Имя схемы.</param>
/// <param name="SchemaExists">Существует ли схема в базе данных.</param>
/// <param name="Tables">Таблицы (relkind = r) с столбцами и ограничениями.</param>
/// <param name="Sequences">Последовательности с атрибутами и владением.</param>
/// <param name="Indexes">Отдельные индексы (не обслуживающие ограничения).</param>
/// <param name="UnsupportedObjectCount">Количество объектов, не входящих в поддерживаемый набор (представления, функции, триггеры и т.п.).</param>
/// <param name="UnsupportedObjectSummary">Краткое описание неподдерживаемых объектов для журнала.</param>
internal sealed record LiveSchema(
    string SchemaName,
    bool SchemaExists,
    IReadOnlyList<TableDefinition> Tables,
    IReadOnlyList<LiveSequence> Sequences,
    IReadOnlyList<IndexDefinition> Indexes,
    int UnsupportedObjectCount,
    string UnsupportedObjectSummary)
{
    /// <summary>
    /// Признак отсутствия пользовательских объектов в схеме (таблицы, последовательности,
    /// индексы, неподдерживаемые объекты). Пустая схема не требует дампа перед изменениями.
    /// </summary>
    internal bool IsEmpty =>
        Tables.Count == 0 &&
        Sequences.Count == 0 &&
        Indexes.Count == 0 &&
        UnsupportedObjectCount == 0;
}
