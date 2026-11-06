using WebShelf.Classes.DB;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты сравнения манифеста каркаса с живой схемой <see cref="SchemaComparer"/>:
/// построение записей выполняется в памяти, без БД. Проверяются нормализация
/// типов и выражений по умолчанию, сопоставление ограничений по виду и
/// определению, сводные свойства diff.
/// </summary>
public class SchemaComparerTests
{
    private const string Schema = "webshelf";

    /// <summary>
    /// Создаёт ожидаемый манифест с одной таблицей и живую схему с той же таблицей.
    /// </summary>
    private static (SchemaManifest Expected, LiveSchema Actual) CreateIdenticalPair()
    {
        ColumnDefinition expectedId = new("id", "bigint", IsNullable: false, DefaultExpression: null, SourceDefinition: "id bigint NOT NULL");
        ColumnDefinition expectedTitle = new("title", "text", IsNullable: false, DefaultExpression: null, SourceDefinition: "title text NOT NULL");
        ConstraintDefinition expectedPrimaryKey = new(
            "books_pkey", SchemaConstraintKind.PrimaryKey, "primary key (id)", "PRIMARY KEY (id)");

        SchemaManifest expected = new(
            Schema,
            [new TableDefinition("books", [expectedId, expectedTitle], [expectedPrimaryKey], "(…)")],
            [new SequenceDefinition("books_id_seq", "START WITH 1")],
            [new IndexDefinition("books_title_idx", "books", IsUnique: false, "books_title_idx|books|plain|title", "CREATE INDEX …")]);

        // Живая схема: типы/определения в форматах каталога PostgreSQL
        ColumnDefinition liveId = new("id", "bigint", IsNullable: false, DefaultExpression: null, SourceDefinition: "id bigint NOT NULL");
        ColumnDefinition liveTitle = new("title", "text", IsNullable: false, DefaultExpression: null, SourceDefinition: "title text NOT NULL");
        ConstraintDefinition livePrimaryKey = new(
            "books_pkey", SchemaConstraintKind.PrimaryKey, "primary key (id)", "PRIMARY KEY (id)");

        LiveSchema actual = new(
            Schema,
            SchemaExists: true,
            [new TableDefinition("books", [liveId, liveTitle], [livePrimaryKey], "(…)")],
            [new LiveSequence("books_id_seq", "bigint", 1, 1, 1, 9223372036854775807, 1, false, null, null)],
            [new IndexDefinition("books_title_idx", "books", IsUnique: false, "books_title_idx|books|plain|title", "CREATE INDEX …")],
            UnsupportedObjectCount: 0,
            UnsupportedObjectSummary: string.Empty);

        return (expected, actual);
    }

    /// <summary>Идентичные структуры совпадают.</summary>
    [Fact]
    public void Compare_IdenticalSchemas_Matches()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();

        SchemaComparison comparison = SchemaComparer.Compare(expected, actual);

        Assert.True(comparison.Matches);
        Assert.True(comparison.Diff.IsEmpty);
        Assert.False(comparison.Diff.OnlyColumnTypeDifferences);
    }

    /// <summary>Отсутствующая схема — расхождение с флагом SchemaMissing.</summary>
    [Fact]
    public void Compare_MissingSchema_Mismatch()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();
        LiveSchema empty = actual with { SchemaExists = false, Tables = [], Sequences = [], Indexes = [] };

        SchemaComparison comparison = SchemaComparer.Compare(expected, empty);

        Assert.False(comparison.Matches);
        Assert.True(comparison.Diff.SchemaMissing);
    }

    /// <summary>Пустой каркас и пустая живая схема (схема существует) совпадают.</summary>
    [Fact]
    public void Compare_EmptySkeletonAndEmptyLiveSchema_Matches()
    {
        SchemaManifest expected = new(Schema, [], [], []);
        LiveSchema actual = new(Schema, SchemaExists: true, [], [], [], 0, string.Empty);

        SchemaComparison comparison = SchemaComparer.Compare(expected, actual);

        Assert.True(comparison.Matches);
    }

    /// <summary>Отсутствующая и лишняя таблица попадают в diff.</summary>
    [Fact]
    public void Compare_MissingAndUnexpectedTables_Reported()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();

        SchemaManifest expectedWithExtra = expected with
        {
            Tables =
            [
                .. expected.Tables,
                new TableDefinition("reviews", [], [], "(…)"),
            ],
        };

        // В живой схеме нет таблицы reviews из каркаса
        SchemaComparison missing = SchemaComparer.Compare(expectedWithExtra, actual);
        Assert.False(missing.Matches);
        Assert.Single(missing.Diff.MissingTables);
        Assert.Empty(missing.Diff.UnexpectedTables);

        // Идентичная пара по-прежнему совпадает
        SchemaComparison identical = SchemaComparer.Compare(expected, actual);
        Assert.True(identical.Matches);

        // В живой схеме есть таблица legacy, отсутствующая в каркасе
        SchemaComparison unexpected = SchemaComparer.Compare(
            expected,
            actual with
            {
                Tables =
                [
                    .. actual.Tables,
                    new TableDefinition("legacy", [], [], "(…)"),
                ],
            });
        Assert.False(unexpected.Matches);
        Assert.Single(unexpected.Diff.UnexpectedTables);
    }

    /// <summary>Синонимы типов (int/int4/integer, varchar/character varying) эквивалентны.</summary>
    [Fact]
    public void Compare_TypeAliases_Match()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();

        SchemaManifest withAliases = expected with
        {
            Tables =
            [
                expected.Tables[0] with
                {
                    Columns =
                    [
                        new ColumnDefinition("id", "int8", false, null, "id int8 NOT NULL"),
                        new ColumnDefinition("title", "varchar(100)", false, null, "title varchar(100) NOT NULL"),
                    ],
                },
            ],
        };
        LiveSchema withCanonical = actual with
        {
            Tables =
            [
                actual.Tables[0] with
                {
                    Columns =
                    [
                        new ColumnDefinition("id", "bigint", false, null, "…"),
                        new ColumnDefinition("title", "character varying(100)", false, null, "…"),
                    ],
                },
            ],
        };

        SchemaComparison comparison = SchemaComparer.Compare(withAliases, withCanonical);

        Assert.True(comparison.Matches);
    }

    /// <summary>Различия типа, nullability и DEFAULT попадают в ChangedColumns с видами расхождений.</summary>
    [Fact]
    public void Compare_ColumnAttributeDifferences_Reported()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();

        SchemaManifest changed = expected with
        {
            Tables =
            [
                expected.Tables[0] with
                {
                    Columns =
                    [
                        new ColumnDefinition("id", "integer", false, null, "id integer NOT NULL"),
                        new ColumnDefinition("title", "text", false, "''", "title text NOT NULL DEFAULT ''"),
                    ],
                },
            ],
        };
        LiveSchema nullabilityDrift = actual with
        {
            Tables =
            [
                actual.Tables[0] with
                {
                    Columns =
                    [
                        new ColumnDefinition("id", "bigint", true, null, "…"),
                        new ColumnDefinition("title", "text", false, null, "…"),
                    ],
                },
            ],
        };

        SchemaComparison comparison = SchemaComparer.Compare(changed, nullabilityDrift);

        Assert.False(comparison.Matches);
        TableDifference table = Assert.Single(comparison.Diff.ChangedTables);
        Assert.Equal(3, table.ChangedColumns.Count);
        Assert.Contains(table.ChangedColumns, column => column.Kind is ColumnDifferenceKind.Type && column.Expected == "integer" && column.Actual == "bigint");
        Assert.Contains(table.ChangedColumns, column => column.Kind is ColumnDifferenceKind.Nullability && column.Expected == "NOT NULL" && column.Actual == "NULL");
        Assert.Contains(table.ChangedColumns, column => column.Kind is ColumnDifferenceKind.Default && column.Expected == "''");
    }

    /// <summary>
    /// Нормализация DEFAULT: nextval без схемы/кавычек эквивалентен полной форме;
    /// приведение ::text у живой схемы отбрасывается; NULL эквивалентен отсутствию.
    /// </summary>
    [Fact]
    public void Compare_DefaultNormalization_Matches()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();

        SchemaManifest withPlainDefaults = expected with
        {
            Tables =
            [
                expected.Tables[0] with
                {
                    Columns =
                    [
                        new ColumnDefinition("id", "bigint", false, "nextval('webshelf.books_id_seq'::regclass)", "…"),
                        new ColumnDefinition("title", "text", false, "'draft'", "…"),
                        new ColumnDefinition("note", "text", true, "NULL", "…"),
                    ],
                },
            ],
        };
        LiveSchema withCatalogDefaults = actual with
        {
            Tables =
            [
                actual.Tables[0] with
                {
                    Columns =
                    [
                        new ColumnDefinition("id", "bigint", false, "nextval('webshelf.books_id_seq'::regclass)", "…"),
                        new ColumnDefinition("title", "text", false, "'draft'::text", "…"),
                        new ColumnDefinition("note", "text", true, null, "…"),
                    ],
                },
            ],
        };

        SchemaComparison comparison = SchemaComparer.Compare(withPlainDefaults, withCatalogDefaults);

        Assert.True(comparison.Matches);
    }

    /// <summary>Ограничения сопоставляются по виду и определению: разные имена при том же определении — совпадение.</summary>
    [Fact]
    public void Compare_SameConstraintDifferentName_Matches()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();

        LiveSchema renamed = actual with
        {
            Tables =
            [
                actual.Tables[0] with
                {
                    Constraints =
                    [
                        new ConstraintDefinition("custom_pk_name", SchemaConstraintKind.PrimaryKey, "primary key (id)", "PRIMARY KEY (id)"),
                    ],
                },
            ],
        };

        SchemaComparison comparison = SchemaComparer.Compare(expected, renamed);

        Assert.True(comparison.Matches);
    }

    /// <summary>Отсутствующее и лишнее ограничение попадают в diff.</summary>
    [Fact]
    public void Compare_ConstraintDifferences_Reported()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();

        SchemaManifest withExtraConstraint = expected with
        {
            Tables =
            [
                expected.Tables[0] with
                {
                    Constraints =
                    [
                        .. expected.Tables[0].Constraints,
                        new ConstraintDefinition("books_title_check", SchemaConstraintKind.Check, "check (title <> '')", "CHECK (title <> '')"),
                    ],
                },
            ],
        };

        SchemaComparison comparison = SchemaComparer.Compare(withExtraConstraint, actual);

        Assert.False(comparison.Matches);
        TableDifference table = Assert.Single(comparison.Diff.ChangedTables);
        Assert.Single(table.MissingConstraints);
        Assert.Empty(table.UnexpectedConstraints);

        SchemaComparison reverse = SchemaComparer.Compare(expected, actual with
        {
            Tables =
            [
                actual.Tables[0] with
                {
                    Constraints =
                    [
                        .. actual.Tables[0].Constraints,
                        new ConstraintDefinition("live_extra", SchemaConstraintKind.Check, "check (legacy)", "CHECK (legacy)"),
                    ],
                },
            ],
        });
        Assert.False(reverse.Matches);
        Assert.Single(Assert.Single(reverse.Diff.ChangedTables).UnexpectedConstraints);
    }

    /// <summary>Отсутствующая, лишняя и изменённая последовательность попадают в diff.</summary>
    [Fact]
    public void Compare_SequenceDifferences_Reported()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();

        SchemaComparison missing = SchemaComparer.Compare(expected, actual with { Sequences = [] });
        Assert.False(missing.Matches);
        Assert.Single(missing.Diff.MissingSequences);

        SchemaComparison extra = SchemaComparer.Compare(expected with { Sequences = [] }, actual);
        Assert.False(extra.Matches);
        Assert.Single(extra.Diff.UnexpectedSequences);
    }

    /// <summary>Отсутствующий, лишний и изменённый индекс попадают в diff.</summary>
    [Fact]
    public void Compare_IndexDifferences_Reported()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();

        SchemaComparison missing = SchemaComparer.Compare(expected, actual with { Indexes = [] });
        Assert.False(missing.Matches);
        Assert.Single(missing.Diff.MissingIndexes);

        SchemaComparison unexpected = SchemaComparer.Compare(
            expected,
            actual with
            {
                Indexes =
                [
                    .. actual.Indexes,
                    new IndexDefinition("legacy_idx", "books", false, "legacy_idx|books|plain|legacy", "CREATE INDEX …"),
                ],
            });
        Assert.False(unexpected.Matches);
        Assert.Single(unexpected.Diff.UnexpectedIndexes);

        SchemaComparison changed = SchemaComparer.Compare(
            expected,
            actual with
            {
                Indexes =
                [
                    actual.Indexes[0] with { Definition = "books_title_idx|books|unique|title", IsUnique = true },
                ],
            });
        Assert.False(changed.Matches);
        Assert.Single(changed.Diff.ChangedIndexes);
    }

    /// <summary>Неподдерживаемые объекты живой схемы — расхождение.</summary>
    [Fact]
    public void Compare_UnsupportedObjects_Mismatch()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();

        SchemaComparison comparison = SchemaComparer.Compare(
            expected,
            actual with { UnsupportedObjectCount = 3, UnsupportedObjectSummary = "представления: 3" });

        Assert.False(comparison.Matches);
        Assert.Equal(3, comparison.Diff.UnsupportedObjectCount);
        Assert.Contains("неподдерживаемые", comparison.Diff.BuildSummary(), StringComparison.Ordinal);
    }

    /// <summary>
    /// OnlyColumnTypeDifferences истинно только когда все прочие списки diff пусты.
    /// </summary>
    [Fact]
    public void Compare_OnlyColumnTypeDifferences_Detected()
    {
        (SchemaManifest expected, LiveSchema actual) = CreateIdenticalPair();

        SchemaManifest withOtherType = expected with
        {
            Tables =
            [
                expected.Tables[0] with
                {
                    Columns = [new ColumnDefinition("id", "integer", false, null, "…"), expected.Tables[0].Columns[1]],
                },
            ],
        };

        SchemaComparison typeOnly = SchemaComparer.Compare(withOtherType, actual);
        Assert.False(typeOnly.Matches);
        Assert.True(typeOnly.Diff.OnlyColumnTypeDifferences);

        SchemaManifest withMissingColumn = expected with
        {
            Tables =
            [
                expected.Tables[0] with
                {
                    Columns =
                    [
                        new ColumnDefinition("id", "integer", false, null, "…"),
                        new ColumnDefinition("isbn", "text", false, null, "…"),
                    ],
                },
            ],
        };

        SchemaComparison withExtraDiff = SchemaComparer.Compare(withMissingColumn, actual);
        Assert.False(withExtraDiff.Matches);
        Assert.False(withExtraDiff.Diff.OnlyColumnTypeDifferences);
    }

    /// <summary>Нормализация типов: проверка канонизации основных псевдонимов.</summary>
    [Theory]
    [InlineData("int", "integer")]
    [InlineData("int4", "integer")]
    [InlineData("int8", "bigint")]
    [InlineData("serial", "integer")]
    [InlineData("bigserial", "bigint")]
    [InlineData("varchar(50)", "character varying(50)")]
    [InlineData("CHARACTER VARYING (100)", "character varying(100)")]
    [InlineData("bool", "boolean")]
    [InlineData("numeric(10,2)", "numeric(10,2)")]
    [InlineData("decimal(8, 3)", "numeric(8,3)")]
    [InlineData("timestamptz", "timestamp with time zone")]
    [InlineData("timestamp", "timestamp without time zone")]
    [InlineData("float", "double precision")]
    [InlineData("float4", "real")]
    [InlineData("int[]", "integer[]")]
    public void NormalizeType_CommonAliases_CanonicalForm(string input, string expected)
    {
        Assert.Equal(expected, SchemaTextNormalizer.NormalizeType(input));
    }

    /// <summary>Нормализация DEFAULT: nextval, приведения, CURRENT_TIMESTAMP, NULL.</summary>
    [Theory]
    [InlineData("nextval('webshelf.books_id_seq'::regclass)", "nextval(books_id_seq)")]
    [InlineData("nextval('books_id_seq'::regclass)", "nextval(books_id_seq)")]
    [InlineData("'draft'::text", "'draft'")]
    [InlineData("CURRENT_TIMESTAMP", "now()")]
    [InlineData("0", "0")]
    [InlineData("NULL", null)]
    [InlineData("", null)]
    public void NormalizeDefaultExpression_Variants(string input, string? expected)
    {
        Assert.Equal(expected, SchemaTextNormalizer.NormalizeDefaultExpression(input, Schema));
    }

    /// <summary>Нормализация определений: квалификация схемой и лишние скобки удаляются.</summary>
    [Theory]
    [InlineData("PRIMARY KEY (id)", "primary key (id)")]
    [InlineData("FOREIGN KEY (a) REFERENCES webshelf.t2(id)", "foreign key (a) references t2(id)")]
    [InlineData("CHECK ((pages > 0))", "check (pages > 0)")]
    [InlineData("UNIQUE (a, b)", "unique (a, b)")]
    public void NormalizeDefinitionText_Variants(string input, string expected)
    {
        Assert.Equal(expected, SchemaTextNormalizer.NormalizeDefinitionText(input, Schema));
    }

    /// <summary>Экранирование идентификаторов для DDL.</summary>
    [Theory]
    [InlineData("books", "books")]
    [InlineData("books_id_seq", "books_id_seq")]
    [InlineData("MixedCase", "\"MixedCase\"")]
    [InlineData("с кав\"ычкой", "\"с кав\"\"ычкой\"")]
    public void QuoteIdentifier_Variants(string input, string expected)
    {
        Assert.Equal(expected, SchemaTextNormalizer.QuoteIdentifier(input));
    }
}
