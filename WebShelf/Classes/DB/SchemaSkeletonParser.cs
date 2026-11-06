using System.Text;

namespace WebShelf.Classes.DB;

/// <summary>
/// Разбор файла-каркаса (чистый SQL DDL) в <see cref="SchemaManifest"/>.
/// </summary>
/// <remarks>
/// Лёгкий парсер ограниченного подмножества DDL (решение ТЗ, риск R8):
/// манифест всегда строится из того же SQL-файла, который применяется к БД,
/// поэтому расхождение «манифест vs SQL» исключено по построению.
/// <para>
/// Поддерживаются операторы: <c>CREATE SCHEMA</c>, <c>CREATE TABLE</c>
/// (столбцы и табличные ограничения, включая inline-объявления в столбцах),
/// <c>ALTER TABLE … ADD CONSTRAINT</c>, <c>ALTER TABLE … ADD COLUMN</c>,
/// <c>CREATE SEQUENCE</c>, <c>CREATE [UNIQUE] INDEX</c>. Любой другой оператор,
/// использование <c>serial</c>/<c>GENERATED … AS IDENTITY</c> или опций таблицы
/// отклоняется исключением — старт приложения прерывается (fail-fast).
/// </para>
/// </remarks>
internal static class SchemaSkeletonParser
{
    /// <summary>Ключевые слова, завершающие разбор типа столбца.</summary>
    private static readonly HashSet<string> ColumnConstraintKeywords =
    [
        "not", "null", "default", "primary", "unique", "references", "check",
        "constraint", "collate", "generated",
    ];

    /// <summary>Типы-синонимы serial: в каркасе требуются явные последовательности.</summary>
    private static readonly HashSet<string> SerialTypeNames = ["serial", "serial2", "serial4", "serial8", "smallserial", "bigserial"];

    /// <summary>
    /// Накопитель разобранных частей таблицы до финальной сборки записей
    /// (ограничения могут добавляться операторами ALTER TABLE после CREATE TABLE).
    /// </summary>
    /// <param name="Name">Имя таблицы.</param>
    /// <param name="Columns">Столбцы.</param>
    /// <param name="Constraints">Ограничения.</param>
    /// <param name="InnerDefinitions">Исходный текст определений в скобках.</param>
    private sealed record TableParts(
        string Name,
        List<ColumnDefinition> Columns,
        List<ConstraintDefinition> Constraints,
        string InnerDefinitions);

    /// <summary>
    /// Разбирает текст каркаса в манифест ожидаемой структуры.
    /// </summary>
    /// <param name="sqlText">Текст SQL-файла каркаса (с комментариями — они игнорируются).</param>
    /// <param name="schemaName">Имя схемы, к которой относится каркас.</param>
    /// <returns>Манифест ожидаемой структуры.</returns>
    /// <exception cref="SchemaSkeletonException">Текст содержит неподдерживаемые или некорректные конструкции.</exception>
    internal static SchemaManifest Parse(string sqlText, string schemaName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sqlText);
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaName);

        string withoutComments = SchemaTextNormalizer.StripComments(sqlText);
        IReadOnlyList<string> statements = SchemaTextNormalizer.SplitStatements(withoutComments);

        List<TableParts> tables = [];
        List<SequenceDefinition> sequences = [];
        List<IndexDefinition> indexes = [];

        foreach (string statement in statements)
        {
            string text = statement.Trim();

            if (text.Length == 0)
            {
                continue;
            }

            string lowered = SchemaTextNormalizer.ToLowerOutsideQuotes(text);

            if (lowered.StartsWith("create schema", StringComparison.Ordinal))
            {
                ParseCreateSchema(text, schemaName);
            }
            else if (lowered.StartsWith("create table", StringComparison.Ordinal))
            {
                ParseCreateTable(text, schemaName, tables);
            }
            else if (lowered.StartsWith("alter table", StringComparison.Ordinal))
            {
                ParseAlterTable(text, schemaName, tables);
            }
            else if (lowered.StartsWith("create unique index", StringComparison.Ordinal) ||
                     lowered.StartsWith("create index", StringComparison.Ordinal))
            {
                ParseCreateIndex(text, schemaName, indexes);
            }
            else if (lowered.StartsWith("create sequence", StringComparison.Ordinal))
            {
                ParseCreateSequence(text, schemaName, sequences);
            }
            else
            {
                throw new SchemaSkeletonException(
                    $"Неподдерживаемый оператор в файле-каркасе: «{Preview(text)}». " +
                    "Поддерживаются только CREATE SCHEMA, CREATE TABLE, ALTER TABLE … ADD CONSTRAINT, CREATE SEQUENCE и CREATE [UNIQUE] INDEX.");
            }
        }

        List<TableDefinition> tableDefinitions =
        [
            .. tables.Select(parts => new TableDefinition(
                parts.Name,
                parts.Columns,
                parts.Constraints,
                $"({parts.InnerDefinitions})")),
        ];

        return new SchemaManifest(schemaName, tableDefinitions, sequences, indexes);
    }

    /// <summary>
    /// Разбирает <c>CREATE SCHEMA [IF NOT EXISTS] имя</c>: имя обязано совпадать с ожидаемой схемой.
    /// </summary>
    private static void ParseCreateSchema(string text, string schemaName)
    {
        int position = "create".Length;
        ExpectWord(text, ref position, "schema");

        if (TryExpectWord(text, ref position, "if"))
        {
            ExpectWord(text, ref position, "not");
            ExpectWord(text, ref position, "exists");
        }

        string name = SchemaTextNormalizer.ReadQualifiedName(text, ref position, schemaName);
        ExpectEndOfStatement(text, position);

        if (!string.Equals(name, schemaName, StringComparison.OrdinalIgnoreCase))
        {
            throw new SchemaSkeletonException(
                $"CREATE SCHEMA объявляет схему «{name}», а ожидается «{schemaName}».");
        }
    }

    /// <summary>
    /// Разбирает <c>CREATE TABLE [IF NOT EXISTS] имя (определения)</c>.
    /// </summary>
    private static void ParseCreateTable(string text, string schemaName, List<TableParts> tables)
    {
        int position = "create".Length;
        ExpectWord(text, ref position, "table");

        if (TryExpectWord(text, ref position, "if"))
        {
            ExpectWord(text, ref position, "not");
            ExpectWord(text, ref position, "exists");
        }

        string tableName = SchemaTextNormalizer.NormalizeIdentifier(
            SchemaTextNormalizer.ReadQualifiedName(text, ref position, schemaName));

        if (FindTable(tables, tableName) is not null)
        {
            throw new SchemaSkeletonException($"Таблица «{tableName}» объявлена в каркасе повторно.");
        }

        SkipWhitespaceAt(text, ref position);

        if (position >= text.Length || text[position] != '(')
        {
            throw new SchemaSkeletonException($"После имени таблицы «{tableName}» ожидается «(»: «{Preview(text)}».");
        }

        string innerDefinitions = ExtractParenthesizedBody(text, ref position);
        ExpectTableEnd(text, position, tableName);

        List<ColumnDefinition> columns = [];
        List<ConstraintDefinition> constraints = [];

        foreach (string member in SchemaTextNormalizer.SplitTopLevelList(innerDefinitions))
        {
            if (member.Length == 0)
            {
                continue;
            }

            ParseTableMember(member, tableName, schemaName, columns, constraints);
        }

        tables.Add(new TableParts(tableName, columns, constraints, innerDefinitions));
    }

    /// <summary>
    /// Разбирает <c>ALTER TABLE имя ADD CONSTRAINT имя вид (…)</c> и
    /// <c>ALTER TABLE имя ADD [COLUMN] [IF NOT EXISTS] определение-столбца</c>.
    /// Таблица должна быть объявлена ранее оператором CREATE TABLE.
    /// </summary>
    private static void ParseAlterTable(string text, string schemaName, List<TableParts> tables)
    {
        int position = "alter".Length;
        ExpectWord(text, ref position, "table");

        string tableName = SchemaTextNormalizer.NormalizeIdentifier(
            SchemaTextNormalizer.ReadQualifiedName(text, ref position, schemaName));

        TableParts table = FindTable(tables, tableName)
            ?? throw new SchemaSkeletonException(
                $"ALTER TABLE ссылается на таблицу «{tableName}», которая не объявлена в каркасе ранее оператором CREATE TABLE.");

        ExpectWord(text, ref position, "add");

        // ADD CONSTRAINT имя тело-ограничения
        if (TryExpectWord(text, ref position, "constraint"))
        {
            string constraintName = SchemaTextNormalizer.ReadIdentifier(text, ref position);
            string body = text[position..].Trim();

            if (body.Length == 0)
            {
                throw new SchemaSkeletonException($"Пустое определение ограничения «{constraintName}» таблицы «{tableName}».");
            }

            table.Constraints.Add(ParseConstraintBody(body, constraintName, schemaName));
            return;
        }

        // ADD [COLUMN] [IF NOT EXISTS] определение-столбца
        _ = TryExpectWord(text, ref position, "column");

        if (TryExpectWord(text, ref position, "if"))
        {
            ExpectWord(text, ref position, "not");
            ExpectWord(text, ref position, "exists");
        }

        string columnDefinition = text[position..].Trim();

        if (columnDefinition.Length == 0)
        {
            throw new SchemaSkeletonException($"Пустое определение столбца в ALTER TABLE для таблицы «{tableName}».");
        }

        ParseColumnDefinition(columnDefinition, tableName, schemaName, table.Columns, table.Constraints);
    }

    /// <summary>
    /// Разбирает <c>CREATE [UNIQUE] INDEX [IF NOT EXISTS] имя ON таблица [USING метод] (столбцы) …</c>.
    /// Остаток после списка столбцов (WHERE, INCLUDE, WITH) сохраняется в исходном тексте,
    /// но в сигнатуру сравнения не входит.
    /// </summary>
    private static void ParseCreateIndex(string text, string schemaName, List<IndexDefinition> indexes)
    {
        int position = "create".Length;
        bool isUnique = TryExpectWord(text, ref position, "unique");
        ExpectWord(text, ref position, "index");

        if (TryExpectWord(text, ref position, "if"))
        {
            ExpectWord(text, ref position, "not");
            ExpectWord(text, ref position, "exists");
        }

        string indexName = SchemaTextNormalizer.NormalizeIdentifier(SchemaTextNormalizer.ReadIdentifier(text, ref position));
        SkipWhitespaceAt(text, ref position);
        ExpectWord(text, ref position, "on");

        string tableName = SchemaTextNormalizer.NormalizeIdentifier(
            SchemaTextNormalizer.ReadQualifiedName(text, ref position, schemaName));

        SkipWhitespaceAt(text, ref position);

        if (TryPeekWord(text, position, "using"))
        {
            position += "using".Length;
            _ = SchemaTextNormalizer.ReadIdentifier(text, ref position);
            SkipWhitespaceAt(text, ref position);
        }

        if (position >= text.Length || text[position] != '(')
        {
            throw new SchemaSkeletonException($"В индексе «{indexName}» после имени таблицы ожидается «(»: «{Preview(text)}».");
        }

        _ = ExtractParenthesizedBody(text, ref position);
        ExpectEndOfStatement(text, position);

        if (indexes.Any(index => string.Equals(index.Name, indexName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new SchemaSkeletonException($"Индекс «{indexName}» объявлен в каркасе повторно.");
        }

        string columns = SchemaTextNormalizer.ExtractIndexColumns(text, schemaName);
        string signature = $"{indexName}|{tableName}|{(isUnique ? "unique" : "plain")}|{columns}";

        indexes.Add(new IndexDefinition(indexName, tableName, isUnique, signature, text));
    }

    /// <summary>
    /// Разбирает <c>CREATE SEQUENCE [IF NOT EXISTS] имя [опции]</c>.
    /// </summary>
    private static void ParseCreateSequence(string text, string schemaName, List<SequenceDefinition> sequences)
    {
        int position = "create".Length;
        ExpectWord(text, ref position, "sequence");

        if (TryExpectWord(text, ref position, "if"))
        {
            ExpectWord(text, ref position, "not");
            ExpectWord(text, ref position, "exists");
        }

        string sequenceName = SchemaTextNormalizer.NormalizeIdentifier(
            SchemaTextNormalizer.ReadQualifiedName(text, ref position, schemaName));

        if (sequences.Any(sequence => string.Equals(sequence.Name, sequenceName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new SchemaSkeletonException($"Последовательность «{sequenceName}» объявлена в каркасе повторно.");
        }

        sequences.Add(new SequenceDefinition(sequenceName, text[position..].Trim()));
    }

    /// <summary>
    /// Разбирает один элемент определения таблицы: столбец, именованное ограничение
    /// или табличное ограничение без имени.
    /// </summary>
    private static void ParseTableMember(
        string member,
        string tableName,
        string schemaName,
        List<ColumnDefinition> columns,
        List<ConstraintDefinition> constraints)
    {
        string lowered = SchemaTextNormalizer.ToLowerOutsideQuotes(member);

        if (lowered.StartsWith("constraint ", StringComparison.Ordinal))
        {
            int position = "constraint".Length;
            string constraintName = SchemaTextNormalizer.ReadIdentifier(member, ref position);
            string body = member[position..].Trim();
            constraints.Add(ParseConstraintBody(body, constraintName, schemaName));
            return;
        }

        if (lowered.StartsWith("primary key", StringComparison.Ordinal))
        {
            constraints.Add(ParseConstraintBody(member, $"{tableName}_pkey", schemaName));
            return;
        }

        if (lowered.StartsWith("foreign key", StringComparison.Ordinal))
        {
            string firstColumn = ExtractFirstColumnName(member, "foreign");
            constraints.Add(ParseConstraintBody(member, $"{tableName}_{firstColumn}_fkey", schemaName));
            return;
        }

        if (lowered.StartsWith("unique", StringComparison.Ordinal) &&
            (lowered["unique".Length] == '(' || lowered["unique".Length] == ' '))
        {
            // Табличное ограничение UNIQUE (столбцы) или UNIQUE (столбцы) — столбец
            // с именем, начинающимся на «unique…», сюда не попадает: за именем идёт тип
            string firstColumn = ExtractFirstColumnName(member, "unique");
            constraints.Add(ParseConstraintBody(member, $"{tableName}_{firstColumn}_key", schemaName));
            return;
        }

        if (lowered.StartsWith("check", StringComparison.Ordinal))
        {
            constraints.Add(ParseConstraintBody(member, $"{tableName}_check", schemaName));
            return;
        }

        if (lowered.StartsWith("exclude", StringComparison.Ordinal))
        {
            throw new SchemaSkeletonException(
                $"Ограничение EXCLUDE в таблице «{tableName}» не поддерживается каркасом: «{Preview(member)}».");
        }

        ParseColumnDefinition(member, tableName, schemaName, columns, constraints);
    }

    /// <summary>
    /// Разбирает определение столбца: имя, тип, NULL/NOT NULL, DEFAULT,
    /// inline-ограничения (PRIMARY KEY, UNIQUE, REFERENCES, CHECK), COLLATE.
    /// </summary>
    private static void ParseColumnDefinition(
        string member,
        string tableName,
        string schemaName,
        List<ColumnDefinition> columns,
        List<ConstraintDefinition> constraints)
    {
        int position = 0;
        string columnName = SchemaTextNormalizer.NormalizeIdentifier(
            SchemaTextNormalizer.ReadIdentifier(member, ref position));

        if (columns.Any(column => string.Equals(column.Name, columnName, StringComparison.OrdinalIgnoreCase)))
        {
            throw new SchemaSkeletonException($"Столбец «{columnName}» таблицы «{tableName}» объявлен повторно.");
        }

        List<SqlToken> tokens = SchemaTextNormalizer.Tokenize(member[position..]);
        int cursor = 0;
        string typeName = AssembleType(tokens, ref cursor, columnName, tableName);

        bool isNullable = true;
        string? defaultExpression = null;

        while (cursor < tokens.Count)
        {
            SqlToken token = tokens[cursor];

            if (!token.IsWord)
            {
                throw new SchemaSkeletonException(
                    $"Не удалось разобрать определение столбца «{columnName}» таблицы «{tableName}»: неожидаемый символ «{token.Text}».");
            }

            string keyword = token.Text.ToLowerInvariant();

            switch (keyword)
            {
                case "not":
                {
                    cursor++;
                    ExpectKeyword(tokens, ref cursor, "null", columnName, tableName);
                    isNullable = false;
                    break;
                }

                case "null":
                {
                    cursor++;
                    isNullable = true;
                    break;
                }

                case "default":
                {
                    cursor++;
                    defaultExpression = ReadExpressionUntilKeyword(tokens, ref cursor);
                    break;
                }

                case "primary":
                {
                    cursor++;
                    ExpectKeyword(tokens, ref cursor, "key", columnName, tableName);
                    constraints.Add(ParseConstraintBody(
                        $"PRIMARY KEY ({columnName})", $"{tableName}_pkey", schemaName));
                    break;
                }

                case "unique":
                {
                    cursor++;
                    constraints.Add(ParseConstraintBody(
                        $"UNIQUE ({columnName})", $"{tableName}_{columnName}_key", schemaName));
                    break;
                }

                case "references":
                {
                    cursor++;
                    string referenceTail = ReadExpressionUntilKeyword(tokens, ref cursor);
                    constraints.Add(ParseConstraintBody(
                        $"FOREIGN KEY ({columnName}) REFERENCES {referenceTail}", $"{tableName}_{columnName}_fkey", schemaName));
                    break;
                }

                case "check":
                {
                    cursor++;
                    SqlToken checkBody = ReadParenthesizedToken(tokens, ref cursor, columnName, tableName);
                    constraints.Add(ParseConstraintBody(
                        $"CHECK {checkBody.Text}", $"{tableName}_{columnName}_check", schemaName));
                    break;
                }

                case "collate":
                {
                    cursor += 2; // ключевое слово и имя collation — в сравнении не участвует (v1)
                    break;
                }

                case "generated":
                {
                    throw new SchemaSkeletonException(
                        $"Столбец «{columnName}» таблицы «{tableName}» объявлен как GENERATED (identity) — " +
                        "в каркасе используйте явный CREATE SEQUENCE и DEFAULT nextval(...).");
                }

                case "constraint":
                {
                    throw new SchemaSkeletonException(
                        $"Именованные ограничения в определении столбца «{columnName}» таблицы «{tableName}» " +
                        "не поддерживаются: вынесите ограничение в секцию таблицы (CONSTRAINT имя …) " +
                        "или в ALTER TABLE … ADD CONSTRAINT.");
                }

                default:
                {
                    throw new SchemaSkeletonException(
                        $"Не удалось разобрать определение столбца «{columnName}» таблицы «{tableName}»: «{Preview(member)}».");
                }
            }
        }

        columns.Add(new ColumnDefinition(
            columnName,
            typeName,
            isNullable,
            defaultExpression,
            BuildColumnSource(columnName, typeName, isNullable, defaultExpression)));
    }

    /// <summary>
    /// Разбирает тело ограничения (без имени) и возвращает его описание с нормализованной сигнатурой.
    /// </summary>
    private static ConstraintDefinition ParseConstraintBody(string body, string constraintName, string schemaName)
    {
        string lowered = SchemaTextNormalizer.ToLowerOutsideQuotes(body);
        SchemaConstraintKind kind;

        if (lowered.StartsWith("primary key", StringComparison.Ordinal))
        {
            kind = SchemaConstraintKind.PrimaryKey;
        }
        else if (lowered.StartsWith("foreign key", StringComparison.Ordinal))
        {
            kind = SchemaConstraintKind.ForeignKey;
        }
        else if (lowered.StartsWith("unique", StringComparison.Ordinal))
        {
            kind = SchemaConstraintKind.Unique;
        }
        else if (lowered.StartsWith("check", StringComparison.Ordinal))
        {
            kind = SchemaConstraintKind.Check;
        }
        else
        {
            throw new SchemaSkeletonException(
                $"Неизвестный вид ограничения: «{Preview(body)}». Поддерживаются PRIMARY KEY, FOREIGN KEY, UNIQUE и CHECK.");
        }

        return new ConstraintDefinition(
            constraintName,
            kind,
            SchemaTextNormalizer.NormalizeDefinitionText(body, schemaName),
            body);
    }

    /// <summary>
    /// Собирает имя типа из лексем до первого ключевого слова ограничения столбца.
    /// </summary>
    private static string AssembleType(List<SqlToken> tokens, ref int cursor, string columnName, string tableName)
    {
        StringBuilder typeBuilder = new();
        bool needSpace = false;
        bool anyToken = false;

        while (cursor < tokens.Count)
        {
            SqlToken token = tokens[cursor];

            if (token.IsWord && ColumnConstraintKeywords.Contains(token.Text.ToLowerInvariant()))
            {
                break;
            }

            if (token.Text.Length > 0 && token.Text[0] == '(')
            {
                // Скобочная группа — модификатор типа: numeric(10,2), varchar(100), timestamp(3)
                typeBuilder.Append(token.Text);
                needSpace = false;
                cursor++;
                anyToken = true;
                continue;
            }

            if (token.Text is "[" or "]")
            {
                // Маркеры массива: integer[], text[][]
                typeBuilder.Append(token.Text);
                needSpace = false;
                cursor++;
                anyToken = true;
                continue;
            }

            if (token.IsWord)
            {
                if (needSpace)
                {
                    typeBuilder.Append(' ');
                }

                typeBuilder.Append(token.Text);
                needSpace = true;
                cursor++;
                anyToken = true;
                continue;
            }

            throw new SchemaSkeletonException(
                $"Не удалось разобрать тип столбца «{columnName}» таблицы «{tableName}»: неожидаемый символ «{token.Text}».");
        }

        if (!anyToken)
        {
            throw new SchemaSkeletonException($"У столбца «{columnName}» таблицы «{tableName}» отсутствует тип.");
        }

        string typeName = typeBuilder.ToString();
        string baseName = typeName.Split('(', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)[0]
            .TrimEnd('[', ']');

        if (SerialTypeNames.Contains(baseName.ToLowerInvariant()))
        {
            throw new SchemaSkeletonException(
                $"Столбец «{columnName}» таблицы «{tableName}» объявлен с типом {baseName}: " +
                "в каркасе используйте явный CREATE SEQUENCE, базовый тип и DEFAULT nextval(...).");
        }

        return typeName;
    }

    /// <summary>
    /// Читает выражение (например, DEFAULT или хвост REFERENCES) до следующего
    /// ключевого слова ограничения столбца верхнего уровня. Лексемы соединяются
    /// с осмысленными пробелами: без пробела перед скобочными группами,
    /// закрывающими символами и операторами (::, .).
    /// </summary>
    private static string ReadExpressionUntilKeyword(List<SqlToken> tokens, ref int cursor)
    {
        StringBuilder expression = new();
        char lastCharacter = '\0';

        while (cursor < tokens.Count)
        {
            SqlToken token = tokens[cursor];

            if (token.IsWord && ColumnConstraintKeywords.Contains(token.Text.ToLowerInvariant()))
            {
                break;
            }

            if (expression.Length > 0 && NeedsSpace(lastCharacter, token.Text))
            {
                expression.Append(' ');
            }

            expression.Append(token.Text);
            lastCharacter = token.Text[^1];
            cursor++;
        }

        return expression.ToString();
    }

    /// <summary>Определяет, нужен ли пробел между последним символом и следующей лексемой.</summary>
    private static bool NeedsSpace(char lastCharacter, string nextToken)
    {
        if (lastCharacter is '(' or '[' or '.')
        {
            return false;
        }

        if (nextToken is ")" or "]" or "," or "." or "::")
        {
            return false;
        }

        if (nextToken.Length > 0 && nextToken[0] is '(' or '[')
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Читает скобочную группу лексем (тело CHECK) и проверяет её наличие.
    /// </summary>
    private static SqlToken ReadParenthesizedToken(List<SqlToken> tokens, ref int cursor, string columnName, string tableName)
    {
        if (cursor >= tokens.Count || tokens[cursor].Text[0] != '(')
        {
            throw new SchemaSkeletonException(
                $"После CHECK столбца «{columnName}» таблицы «{tableName}» ожидается скобочное выражение.");
        }

        SqlToken token = tokens[cursor];
        cursor++;
        return token;
    }

    /// <summary>
    /// Формирует исходный текст определения столбца для контекста ADD COLUMN.
    /// </summary>
    private static string BuildColumnSource(string columnName, string typeName, bool isNullable, string? defaultExpression)
    {
        List<string> parts = [columnName, typeName];

        if (!isNullable)
        {
            parts.Add("NOT NULL");
        }

        if (defaultExpression is not null)
        {
            parts.Add($"DEFAULT {defaultExpression}");
        }

        return string.Join(' ', parts);
    }

    /// <summary>
    /// Извлекает имя первого столбца из табличного ограничения вида
    /// <c>FOREIGN KEY (col, …)</c> / <c>UNIQUE (col, …)</c> — для генерации имени по умолчанию.
    /// </summary>
    private static string ExtractFirstColumnName(string member, string constraintKeyword)
    {
        List<SqlToken> tokens = SchemaTextNormalizer.Tokenize(member);
        int keywordIndex = tokens.FindIndex(
            token => token.IsWord && string.Equals(token.Text, constraintKeyword, StringComparison.OrdinalIgnoreCase));

        if (keywordIndex < 0 || keywordIndex + 1 >= tokens.Count || tokens[keywordIndex + 1].Text[0] != '(')
        {
            throw new SchemaSkeletonException($"Не удалось разобрать ограничение: «{Preview(member)}».");
        }

        string inner = tokens[keywordIndex + 1].Text[1..^1];
        string first = inner.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)[0];
        return SchemaTextNormalizer.NormalizeIdentifier(first);
    }

    /// <summary>
    /// Извлекает содержимое скобочной группы, начинающейся в текущей позиции,
    /// и сдвигает позицию за закрывающую скобку.
    /// </summary>
    private static string ExtractParenthesizedBody(string text, ref int position)
    {
        int start = position + 1;
        int depth = 1;
        int cursor = position + 1;

        while (cursor < text.Length && depth > 0)
        {
            char current = text[cursor];

            if (current is '\'' or '"')
            {
                SkipQuoted(text, ref cursor, current);
                continue;
            }

            if (current == '(')
            {
                depth++;
            }
            else if (current == ')')
            {
                depth--;

                if (depth == 0)
                {
                    break;
                }
            }

            cursor++;
        }

        if (depth != 0)
        {
            throw new SchemaSkeletonException($"Скобки не сбалансированы: «{Preview(text)}».");
        }

        string body = text[start..cursor].Trim();
        position = cursor + 1;
        return body;
    }

    /// <summary>Пропускает квотированный фрагмент, начиная с открывающей кавычки.</summary>
    private static void SkipQuoted(string text, ref int position, char quote)
    {
        position++;

        while (position < text.Length)
        {
            if (text[position] == quote)
            {
                if (position + 1 < text.Length && text[position + 1] == quote)
                {
                    position += 2;
                    continue;
                }

                position++;
                return;
            }

            position++;
        }
    }

    /// <summary>Пропускает пробелы в позиции.</summary>
    private static void SkipWhitespaceAt(string text, ref int position)
    {
        while (position < text.Length && char.IsWhiteSpace(text[position]))
        {
            position++;
        }
    }

    /// <summary>Ожидает ключевое слово в позиции и сдвигает позицию за него.</summary>
    private static void ExpectWord(string text, ref int position, string word)
    {
        if (!TryExpectWord(text, ref position, word))
        {
            throw new SchemaSkeletonException($"В позиции {position} ожидалось ключевое слово «{word}»: «{Preview(text)}».");
        }
    }

    /// <summary>Пытается прочитать ключевое слово в позиции; успех — позиция сдвигается.</summary>
    private static bool TryExpectWord(string text, ref int position, string word)
    {
        SkipWhitespaceAt(text, ref position);

        if (position + word.Length > text.Length)
        {
            return false;
        }

        string candidate = text[position..(position + word.Length)];

        if (!string.Equals(candidate, word, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        int after = position + word.Length;

        if (after < text.Length && (char.IsLetterOrDigit(text[after]) || text[after] is '_' or '$'))
        {
            return false;
        }

        position = after;
        return true;
    }

    /// <summary>Проверяет ключевое слово в позиции без сдвига.</summary>
    private static bool TryPeekWord(string text, int position, string word)
    {
        int localPosition = position;
        return TryExpectWord(text, ref localPosition, word);
    }

    /// <summary>Ожидает ключевое слово-лексему в списке лексем.</summary>
    private static void ExpectKeyword(List<SqlToken> tokens, ref int cursor, string word, string columnName, string tableName)
    {
        if (cursor < tokens.Count &&
            tokens[cursor].IsWord &&
            string.Equals(tokens[cursor].Text, word, StringComparison.OrdinalIgnoreCase))
        {
            cursor++;
            return;
        }

        throw new SchemaSkeletonException(
            $"В определении столбца «{columnName}» таблицы «{tableName}» ожидалось ключевое слово «{word}».");
    }

    /// <summary>Проверяет, что после оператора не осталось посторонних опций.</summary>
    private static void ExpectEndOfStatement(string text, int position)
    {
        string tail = text[position..].Trim();

        if (tail.Length != 0)
        {
            throw new SchemaSkeletonException($"Неподдерживаемый хвост оператора: «{Preview(tail)}».");
        }
    }

    /// <summary>Проверяет, что после определения таблицы не осталось опций (WITH, INHERITS и т.п.).</summary>
    private static void ExpectTableEnd(string text, int position, string tableName)
    {
        string tail = text[position..].Trim();

        if (tail.Length != 0)
        {
            throw new SchemaSkeletonException(
                $"Опции таблицы «{tableName}» не поддерживаются: «{Preview(tail)}».");
        }
    }

    /// <summary>Ищет таблицу по имени (без учёта регистра).</summary>
    private static TableParts? FindTable(List<TableParts> tables, string tableName)
    {
        return tables.FirstOrDefault(
            candidate => string.Equals(candidate.Name, tableName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Возвращает начало текста (до 120 символов) для сообщений об ошибках.</summary>
    private static string Preview(string text)
    {
        return text.Length <= 120 ? text.ReplaceLineEndings(" ") : text[..120].ReplaceLineEndings(" ") + "…";
    }
}
