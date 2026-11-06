using System.Text;
using System.Text.RegularExpressions;

namespace WebShelf.Classes.DB;

/// <summary>
/// Лексема SQL-текста: слово, квотированный идентификатор, строковый литерал,
/// сбалансированная скобочная группа или одиночный символ (оператор).
/// </summary>
/// <param name="Text">Текст лексемы (литералы и квотированные идентификаторы — вместе с ограничителями).</param>
/// <param name="IsWord">Признак слова (последовательность букв, цифр, <c>_</c>, <c>$</c>).</param>
internal readonly record struct SqlToken(string Text, bool IsWord);

/// <summary>
/// Утилиты обработки SQL-текста каркаса и живой схемы: удаление комментариев,
/// разбиение на операторы и элементы, лексический разбор и нормализация
/// идентификаторов, типов и выражений по умолчанию для сравнения структур.
/// </summary>
/// <remarks>
/// Нормализация решает задачу сравнения «каркас vs живая схема» без полного
/// AST-разбора: одинаковые по смыслу, но записанные по-разному фрагменты
/// (псевдонимы типов, квалификация схемой, лишние скобки, регистр) приводятся
/// к единой сигнатуре. Поддерживается ограниченный набор объектов
/// (таблицы, столбцы, PK/FK/UNIQUE/CHECK, индексы, sequences) — см. ТЗ
/// «Сервисная инфраструктура БД».
/// </remarks>
internal static partial class SchemaTextNormalizer
{
    /// <summary>
    /// Синонимы имён типов PostgreSQL: ключ — псевдоним в нижнем регистре,
    /// значение — каноническая форма (как её возвращает <c>format_type</c>).
    /// Порядок важен: более длинные имена проверяются первыми.
    /// </summary>
    private static readonly (string Alias, string Canonical)[] TypeAliases =
    [
        ("timestamp with time zone", "timestamp with time zone"),
        ("timestamp without time zone", "timestamp without time zone"),
        ("time with time zone", "time with time zone"),
        ("time without time zone", "time without time zone"),
        ("character varying", "character varying"),
        ("double precision", "double precision"),
        ("timestamptz", "timestamp with time zone"),
        ("timetz", "time with time zone"),
        ("smallserial", "smallint"),
        ("bigserial", "bigint"),
        ("timestamp", "timestamp without time zone"),
        ("varbit", "bit varying"),
        ("smallint", "smallint"),
        ("serial4", "integer"),
        ("serial8", "bigint"),
        ("serial2", "smallint"),
        ("integer", "integer"),
        ("numeric", "numeric"),
        ("decimal", "numeric"),
        ("varchar", "character varying"),
        ("boolean", "boolean"),
        ("serial", "integer"),
        ("bigint", "bigint"),
        ("bit varying", "bit varying"),
        ("float8", "double precision"),
        ("float4", "real"),
        ("float", "double precision"),
        ("int8", "bigint"),
        ("int4", "integer"),
        ("int2", "smallint"),
        ("char", "character"),
        ("bool", "boolean"),
        ("int", "integer"),
        ("real", "real"),
        ("time", "time without time zone"),
    ];

    /// <summary>
    /// Удаляет однострочные (<c>--</c>) и блочные (<c>/* */</c>) комментарии,
    /// не затрагивая строковые литералы и квотированные идентификаторы.
    /// </summary>
    /// <param name="sql">Исходный SQL-текст.</param>
    /// <returns>Текст без комментариев.</returns>
    internal static string StripComments(string sql)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sql);

        StringBuilder builder = new(sql.Length);
        int position = 0;

        while (position < sql.Length)
        {
            char current = sql[position];

            if (current is '\'' or '"')
            {
                CopyQuoted(sql, ref position, builder, current);
                continue;
            }

            if (current == '-' && position + 1 < sql.Length && sql[position + 1] == '-')
            {
                while (position < sql.Length && sql[position] != '\n')
                {
                    position++;
                }

                continue;
            }

            if (current == '/' && position + 1 < sql.Length && sql[position + 1] == '*')
            {
                position += 2;

                while (position + 1 < sql.Length && !(sql[position] == '*' && sql[position + 1] == '/'))
                {
                    position++;
                }

                position = Math.Min(position + 2, sql.Length);
                continue;
            }

            builder.Append(current);
            position++;
        }

        return builder.ToString();
    }

    /// <summary>
    /// Разбивает SQL-текст на операторы по символу <c>;</c> вне строковых литералов
    /// и квотированных идентификаторов. Завершающий оператор без <c>;</c> допускается.
    /// </summary>
    /// <param name="sql">Текст без комментариев.</param>
    /// <returns>Перечень операторов (возможно, с пустыми элементами).</returns>
    internal static IReadOnlyList<string> SplitStatements(string sql)
    {
        ArgumentNullException.ThrowIfNull(sql);

        List<string> statements = [];
        StringBuilder current = new();
        int position = 0;

        while (position < sql.Length)
        {
            char currentChar = sql[position];

            if (currentChar is '\'' or '"')
            {
                CopyQuoted(sql, ref position, current, currentChar);
                continue;
            }

            if (currentChar == ';')
            {
                statements.Add(current.ToString());
                current.Clear();
                position++;
                continue;
            }

            current.Append(currentChar);
            position++;
        }

        if (current.Length > 0)
        {
            statements.Add(current.ToString());
        }

        return statements;
    }

    /// <summary>
    /// Разбивает список определений (например, внутренность <c>CREATE TABLE ( … )</c>)
    /// на элементы верхнего уровня по запятым, не заходя внутрь скобок, строковых
    /// литералов и квотированных идентификаторов.
    /// </summary>
    /// <param name="text">Текст списка.</param>
    /// <returns>Элементы списка без окружающих пробелов.</returns>
    internal static IReadOnlyList<string> SplitTopLevelList(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        List<string> items = [];
        StringBuilder current = new();
        int depth = 0;
        int position = 0;

        while (position < text.Length)
        {
            char currentChar = text[position];

            if (currentChar is '\'' or '"')
            {
                CopyQuoted(text, ref position, current, currentChar);
                continue;
            }

            if (currentChar == '(')
            {
                depth++;
            }
            else if (currentChar == ')')
            {
                depth--;
            }

            if (currentChar == ',' && depth == 0)
            {
                items.Add(current.ToString().Trim());
                current.Clear();
                position++;
                continue;
            }

            current.Append(currentChar);
            position++;
        }

        if (current.Length > 0)
        {
            items.Add(current.ToString().Trim());
        }

        return items;
    }

    /// <summary>
    /// Разбивает текст на лексемы: слова, строковые литералы, квотированные
    /// идентификаторы, сбалансированные скобочные группы и одиночные символы.
    /// </summary>
    /// <param name="text">Текст для разбора.</param>
    /// <returns>Перечень лексем.</returns>
    internal static List<SqlToken> Tokenize(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        List<SqlToken> tokens = [];
        int position = 0;

        while (position < text.Length)
        {
            char current = text[position];

            if (char.IsWhiteSpace(current))
            {
                position++;
                continue;
            }

            if (current is '\'' or '"')
            {
                StringBuilder quoted = new();
                CopyQuoted(text, ref position, quoted, current);
                tokens.Add(new SqlToken(quoted.ToString(), IsWord: false));
                continue;
            }

            if (current == '(')
            {
                StringBuilder group = new();
                (int end, _) = FindBalancedEnd(text, position);
                group.Append(text[position..end]);
                tokens.Add(new SqlToken(group.ToString(), IsWord: false));
                position = end;
                continue;
            }

            if (char.IsLetterOrDigit(current) || current is '_' or '$')
            {
                int start = position;

                while (position < text.Length &&
                       (char.IsLetterOrDigit(text[position]) || text[position] is '_' or '$'))
                {
                    position++;
                }

                tokens.Add(new SqlToken(text[start..position], IsWord: true));
                continue;
            }

            tokens.Add(new SqlToken(current.ToString(), IsWord: false));
            position++;
        }

        return tokens;
    }

    /// <summary>
    /// Читает идентификатор (квотированный или простой) с текущей позиции.
/// Квотированный идентификатор возвращается без кавычек.
    /// </summary>
    /// <param name="text">Текст.</param>
    /// <param name="position">Позиция чтения (сдвигается за идентификатор).</param>
    /// <returns>Имя идентификатора без кавычек.</returns>
    /// <exception cref="SchemaSkeletonException">Идентификатор отсутствует в этой позиции.</exception>
    internal static string ReadIdentifier(string text, ref int position)
    {
        ArgumentNullException.ThrowIfNull(text);
        SkipWhitespace(text, ref position);

        if (position >= text.Length)
        {
            throw new SchemaSkeletonException($"Ожидался идентификатор, но текст закончился: «{Preview(text, text.Length)}».");
        }

        if (text[position] == '"')
        {
            StringBuilder quoted = new();
            CopyQuoted(text, ref position, quoted, '"');
            string raw = quoted.ToString();
            return raw[1..^1].Replace("\"\"", "\"");
        }

        int start = position;

        while (position < text.Length &&
               (char.IsLetterOrDigit(text[position]) || text[position] is '_' or '$'))
        {
            position++;
        }

        if (position == start)
        {
            throw new SchemaSkeletonException($"Ожидался идентификатор в позиции {position}: «{Preview(text, position)}».");
        }

        return text[start..position];
    }

    /// <summary>
    /// Читает возможно квалифицированное имя (<c>schema.name</c> или <c>name</c>)
    /// и возвращает неквалифицированное имя. Квалификация схемой, отличной от
    /// ожидаемой, отклоняется.
    /// </summary>
    /// <param name="text">Текст.</param>
    /// <param name="position">Позиция чтения.</param>
    /// <param name="expectedSchema">Имя ожидаемой схемы.</param>
    /// <returns>Неквалифицированное имя объекта.</returns>
    /// <exception cref="SchemaSkeletonException">Имя относится к другой схеме или отсутствует.</exception>
    internal static string ReadQualifiedName(string text, ref int position, string expectedSchema)
    {
        string first = ReadIdentifier(text, ref position);
        int saved = position;
        SkipWhitespace(text, ref position);

        if (position < text.Length && text[position] == '.')
        {
            position++;
            string second = ReadIdentifier(text, ref position);

            if (!string.Equals(first, expectedSchema, StringComparison.OrdinalIgnoreCase))
            {
                throw new SchemaSkeletonException(
                    $"Объект «{first}.{second}» относится к схеме «{first}», ожидается схема «{expectedSchema}».");
            }

            return second;
        }

        position = saved;
        return first;
    }

    /// <summary>
    /// Приводит идентификатор к нижнему регистру (некавычанные идентификаторы
    /// PostgreSQL регистронезависимы; каркас использует только строчные имена).
    /// </summary>
    /// <param name="identifier">Имя идентификатора.</param>
    /// <returns>Имя в нижнем регистре.</returns>
    internal static string NormalizeIdentifier(string identifier)
    {
        return identifier.Trim().ToLowerInvariant();
    }

    /// <summary>
    /// Приводит текст к нижнему регистру вне строковых литералов и квотированных
    /// идентификаторов (для классификации операторов по ключевым словам).
    /// </summary>
    /// <param name="text">Исходный текст.</param>
    /// <returns>Текст в нижнем регистре вне кавычек.</returns>
    internal static string ToLowerOutsideQuotes(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        StringBuilder builder = new(text.Length);
        int position = 0;

        while (position < text.Length)
        {
            char current = text[position];

            if (current is '\'' or '"')
            {
                CopyQuoted(text, ref position, builder, current);
                continue;
            }

            builder.Append(char.ToLowerInvariant(current));
            position++;
        }

        return builder.ToString();
    }

    /// <summary>
    /// Нормализует определение объекта (ограничение, выражение индекса) для сравнения:
    /// нижний регистр вне кавычек, схлопывание пробелов, удаление квалификации
    /// ожидаемой схемой и лишних пар скобок.
    /// </summary>
    /// <param name="text">Исходный текст определения.</param>
    /// <param name="schemaName">Имя схемы, квалификация которой удаляется.</param>
    /// <returns>Нормализованная сигнатура определения.</returns>
    internal static string NormalizeDefinitionText(string text, string schemaName)
    {
        ArgumentNullException.ThrowIfNull(text);

        string lowered = ToLowerOutsideQuotes(text);
        string collapsed = CollapseWhitespace(lowered).Trim();
        string withoutSchema = StripSchemaQualification(collapsed, schemaName);

        // Повторные скобки схлопываются: pg_get_constraintdef оборачивает выражения
        // CHECK в дополнительные скобки (CHECK ((x > 0))), а каркас пишет CHECK (x > 0)
        while (withoutSchema.Contains("((", StringComparison.Ordinal) ||
               withoutSchema.Contains("))", StringComparison.Ordinal))
        {
            withoutSchema = withoutSchema.Replace("((", "(", StringComparison.Ordinal)
                .Replace("))", ")", StringComparison.Ordinal);
        }

        return withoutSchema.Trim();
    }

    /// <summary>
    /// Нормализует имя типа данных: синонимы (<c>int4</c>, <c>serial</c>, <c>varchar</c> и т.п.)
    /// приводятся к канонической форме <c>format_type</c>, пробелы вокруг модификаторов
    /// схлопываются (<c>numeric(10, 2)</c> → <c>numeric(10,2)</c>).
    /// </summary>
    /// <param name="typeName">Исходный текст типа.</param>
    /// <returns>Каноническая форма типа.</returns>
    internal static string NormalizeType(string typeName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(typeName);

        string normalized = CollapseWhitespace(typeName.Trim().ToLowerInvariant())
            .Replace(" (", "(", StringComparison.Ordinal)
            .Replace(", ", ",", StringComparison.Ordinal)
            .Replace(" ,", ",", StringComparison.Ordinal)
            .Replace(" []", "[]", StringComparison.Ordinal)
            .Replace("[] ", "[]", StringComparison.Ordinal);

        foreach ((string alias, string canonical) in TypeAliases)
        {
            if (!normalized.StartsWith(alias, StringComparison.Ordinal))
            {
                continue;
            }

            if (normalized.Length == alias.Length ||
                normalized[alias.Length] is '(' or '[')
            {
                return canonical + normalized[alias.Length..];
            }
        }

        return normalized;
    }

    /// <summary>
    /// Нормализует выражение DEFAULT для сравнения: <see langword="null"/> и
    /// <c>NULL</c> эквивалентны отсутствию значения; <c>nextval</c> приводится к имени
    /// последовательности без схемы и кавычек; приведения <c>::type</c>, которые
    /// <c>pg_get_expr</c> добавляет к литералам, удаляются; <c>CURRENT_TIMESTAMP</c>
    /// эквивалентен <c>now()</c>.
    /// </summary>
    /// <param name="defaultExpression">Исходное выражение (может быть <see langword="null"/>).</param>
    /// <param name="schemaName">Имя схемы, квалификация которой удаляется.</param>
    /// <returns>Нормализованное выражение или <see langword="null"/>, если значения по умолчанию нет.</returns>
    internal static string? NormalizeDefaultExpression(string? defaultExpression, string schemaName)
    {
        if (string.IsNullOrWhiteSpace(defaultExpression))
        {
            return null;
        }

        string normalized = NormalizeDefinitionText(defaultExpression, schemaName);

        if (normalized.Length == 0 || normalized is "null")
        {
            return null;
        }

        Match nextvalMatch = NextvalRegex.Match(normalized);

        if (nextvalMatch.Success)
        {
            string sequenceName = nextvalMatch.Groups[1].Value;
            int lastDot = sequenceName.LastIndexOf('.');

            if (lastDot >= 0)
            {
                sequenceName = sequenceName[(lastDot + 1)..];
            }

            sequenceName = sequenceName.Trim('"').ToLowerInvariant();
            return $"nextval({sequenceName})";
        }

        normalized = normalized.Replace("current_timestamp", "now()", StringComparison.Ordinal);
        normalized = TypeCastRegex.Replace(normalized, string.Empty);
        return CollapseWhitespace(normalized).Trim();
    }

    /// <summary>
    /// Экранирует идентификатор для подстановки в DDL: простые строчные имена
    /// остаются как есть, остальные заключаются в двойные кавычки с удвоением
    /// внутренних кавычек.
    /// </summary>
    /// <param name="identifier">Имя объекта.</param>
    /// <returns>Идентификатор, безопасный для DDL.</returns>
    internal static string QuoteIdentifier(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        return SimpleIdentifierRegex.IsMatch(identifier)
            ? identifier
            : "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    /// <summary>
    /// Формирует квалифицированное имя <c>schema.name</c> с экранированием частей.
    /// </summary>
    /// <param name="schemaName">Имя схемы.</param>
    /// <param name="objectName">Имя объекта.</param>
    /// <returns>Экранированное квалифицированное имя.</returns>
    internal static string QuoteQualifiedName(string schemaName, string objectName)
    {
        return $"{QuoteIdentifier(schemaName)}.{QuoteIdentifier(objectName)}";
    }

    /// <summary>
    /// Извлекает выражение столбцов из оператора <c>CREATE INDEX</c> — содержимое
    /// первой скобочной группы после <c>ON таблица [USING метод]</c>.
    /// </summary>
    /// <param name="createIndexStatement">Текст оператора (каркас или pg_get_indexdef).</param>
    /// <param name="schemaName">Имя схемы.</param>
    /// <returns>Нормализованное выражение столбцов индекса.</returns>
    /// <exception cref="SchemaSkeletonException">Оператор не удалось разобрать.</exception>
    internal static string ExtractIndexColumns(string createIndexStatement, string schemaName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(createIndexStatement);

        List<SqlToken> tokens = Tokenize(createIndexStatement);
        int onIndex = -1;

        for (int i = 0; i < tokens.Count; i++)
        {
            if (tokens[i].IsWord &&
                string.Equals(tokens[i].Text, "on", StringComparison.OrdinalIgnoreCase))
            {
                onIndex = i;
                break;
            }
        }

        if (onIndex < 0 || onIndex + 1 >= tokens.Count)
        {
            throw new SchemaSkeletonException(
                $"Не удалось разобрать оператор CREATE INDEX: «{Preview(createIndexStatement, 0)}».");
        }

        int cursor = onIndex + 1;
        _ = ReadQualifiedNameFromTokens(tokens, ref cursor);

        if (cursor < tokens.Count &&
            tokens[cursor].IsWord &&
            string.Equals(tokens[cursor].Text, "using", StringComparison.OrdinalIgnoreCase))
        {
            cursor += 2; // USING метод
        }

        if (cursor >= tokens.Count || tokens[cursor].Text[0] != '(')
        {
            throw new SchemaSkeletonException(
                $"Не удалось извлечь список столбцов индекса: «{Preview(createIndexStatement, 0)}».");
        }

        string columns = tokens[cursor].Text;
        return NormalizeDefinitionText(columns[1..^1], schemaName);
    }

    /// <summary>
    /// Пропускает пробелы с текущей позиции.
    /// </summary>
    private static void SkipWhitespace(string text, ref int position)
    {
        while (position < text.Length && char.IsWhiteSpace(text[position]))
        {
            position++;
        }
    }

    /// <summary>
    /// Копирует квотированный фрагмент (строковый литерал или квотированный
    /// идентификатор) с обработкой удвоенных кавычек.
    /// </summary>
    private static void CopyQuoted(string text, ref int position, StringBuilder builder, char quote)
    {
        builder.Append(text[position]);
        position++;

        while (position < text.Length)
        {
            if (text[position] == quote)
            {
                if (position + 1 < text.Length && text[position + 1] == quote)
                {
                    builder.Append(text[position]);
                    builder.Append(text[position + 1]);
                    position += 2;
                    continue;
                }

                builder.Append(text[position]);
                position++;
                return;
            }

            builder.Append(text[position]);
            position++;
        }
    }

    /// <summary>
    /// Находит позицию после закрывающей скобки для скобочной группы,
    /// начинающейся в <paramref name="openPosition"/>.
    /// </summary>
    /// <returns>Позиция после закрывающей скобки и глубина в конце (0 при успехе).</returns>
    /// <exception cref="SchemaSkeletonException">Скобки не сбалансированы.</exception>
    private static (int End, int Depth) FindBalancedEnd(string text, int openPosition)
    {
        int depth = 0;
        int position = openPosition;

        while (position < text.Length)
        {
            char current = text[position];

            if (current is '\'' or '"')
            {
                StringBuilder ignored = new();
                CopyQuoted(text, ref position, ignored, current);
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
                    return (position + 1, 0);
                }
            }

            position++;
        }

        throw new SchemaSkeletonException($"Скобки не сбалансированы: «{Preview(text, openPosition)}».");
    }

    /// <summary>
    /// Читает возможно квалифицированное имя из списка лексем.
    /// </summary>
    private static string ReadQualifiedNameFromTokens(List<SqlToken> tokens, ref int cursor)
    {
        string first = tokens[cursor].Text;
        cursor++;

        if (cursor < tokens.Count && tokens[cursor].Text == ".")
        {
            cursor++;
            string second = tokens[cursor].Text;
            cursor++;
            return second;
        }

        return first;
    }

    /// <summary>
    /// Удаляет квалификацию схемой (<c>webshelf.</c> и <c>"webshelf".</c>) из текста.
    /// Замена применяется и внутри строковых литералов: функция детерминирована,
    /// обе стороны сравнения обрабатываются одинаково.
    /// </summary>
    private static string StripSchemaQualification(string text, string schemaName)
    {
        string loweredSchema = schemaName.ToLowerInvariant();
        string quotedForm = "\"" + loweredSchema + "\".";
        string plainForm = loweredSchema + ".";

        string result = text.Replace(quotedForm, string.Empty, StringComparison.Ordinal);
        result = result.Replace(plainForm, string.Empty, StringComparison.Ordinal);
        return result;
    }

    /// <summary>
    /// Схлопывает последовательные пробелы в один.
    /// </summary>
    private static string CollapseWhitespace(string text)
    {
        StringBuilder builder = new(text.Length);
        bool lastWasWhitespace = true;

        foreach (char current in text)
        {
            if (char.IsWhiteSpace(current))
            {
                if (!lastWasWhitespace)
                {
                    builder.Append(' ');
                    lastWasWhitespace = true;
                }

                continue;
            }

            builder.Append(current);
            lastWasWhitespace = false;
        }

        return builder.ToString().Trim();
    }

    /// <summary>
    /// Возвращает начало текста (до 120 символов) для сообщений об ошибках.
    /// </summary>
    private static string Preview(string text, int position)
    {
        int start = Math.Max(0, position - 20);
        int length = Math.Min(120, text.Length - start);
        return text.Substring(start, length).ReplaceLineEndings(" ");
    }

    /// <summary>Выражение <c>nextval('имя')</c>.</summary>
    [GeneratedRegex("""nextval\s*\(\s*'([^']*)'""", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NextvalRegex { get; }

    /// <summary>Приведение типа <c>::type</c> (в том числе многословное и с модификатором).</summary>
    [GeneratedRegex("""::[a-z_][a-z0-9_]*(?:\s+[a-z_][a-z0-9_]*)*(?:\(\d+(?:\s*,\s*\d+)?\))?(?:\[\])*""", RegexOptions.CultureInvariant)]
    private static partial Regex TypeCastRegex { get; }

    /// <summary>Простой идентификатор, не требующий экранирования.</summary>
    [GeneratedRegex("""^[a-z_][a-z0-9_]*$""", RegexOptions.CultureInvariant)]
    private static partial Regex SimpleIdentifierRegex { get; }
}
