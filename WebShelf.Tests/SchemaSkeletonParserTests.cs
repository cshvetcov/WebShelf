using WebShelf.Classes.DB;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты парсера файла-каркаса <see cref="SchemaSkeletonParser"/>: разбор
/// поддерживаемого подмножества DDL, нормализация, отклонение неподдерживаемых
/// конструкций. Тесты чистые — без обращения к БД и файловой системе.
/// </summary>
public class SchemaSkeletonParserTests
{
    /// <summary>Схема по умолчанию для всех тестов.</summary>
    private const string Schema = "webshelf";

    /// <summary>
    /// Полный образец каркаса с таблицами, ограничениями, последовательностью
    /// и индексами разбирается в манифест с ожидаемым содержимым.
    /// </summary>
    [Fact]
    public void Parse_FullSkeleton_BuildsExpectedManifest()
    {
        const string sql = """
            -- Каркас тестовой схемы
            CREATE SCHEMA IF NOT EXISTS webshelf;

            CREATE TABLE webshelf.authors (
                id     bigint       NOT NULL,
                name   varchar(100) NOT NULL,
                email  text         NULL,
                CONSTRAINT authors_pkey PRIMARY KEY (id),
                CONSTRAINT authors_email_key UNIQUE (email)
            );

            CREATE TABLE webshelf.books (
                id         bigint                       NOT NULL,
                title      text                         NOT NULL,
                author_id  bigint                       NOT NULL,
                pages      integer                      NOT NULL DEFAULT 0,
                created_at timestamp with time zone     NOT NULL DEFAULT now(),
                CONSTRAINT books_pkey PRIMARY KEY (id),
                CONSTRAINT books_author_fkey FOREIGN KEY (author_id) REFERENCES webshelf.authors(id) ON DELETE CASCADE,
                CONSTRAINT books_pages_check CHECK (pages > 0)
            );

            ALTER TABLE webshelf.books ADD CONSTRAINT books_title_nonempty CHECK (char_length(title) > 0);

            CREATE SEQUENCE webshelf.docs_id_seq AS bigint START WITH 10 INCREMENT BY 5;

            CREATE INDEX books_title_idx ON webshelf.books (title);
            CREATE UNIQUE INDEX books_author_title_idx ON webshelf.books USING btree (author_id, lower(title));
            """;

        SchemaManifest manifest = SchemaSkeletonParser.Parse(sql, Schema);

        Assert.Equal(2, manifest.Tables.Count);
        Assert.Single(manifest.Sequences);
        Assert.Equal(2, manifest.Indexes.Count);

        TableDefinition authors = manifest.Tables.Single(table => table.Name == "authors");
        Assert.Equal(3, authors.Columns.Count);
        Assert.Equal(2, authors.Constraints.Count);

        ColumnDefinition id = authors.Columns[0];
        Assert.Equal("id", id.Name);
        Assert.Equal("bigint", id.TypeName);
        Assert.False(id.IsNullable);
        Assert.Null(id.DefaultExpression);

        ColumnDefinition email = authors.Columns[2];
        Assert.Equal("email", email.Name);
        Assert.Equal("text", email.TypeName);
        Assert.True(email.IsNullable);

        TableDefinition books = manifest.Tables.Single(table => table.Name == "books");
        ColumnDefinition pages = books.Columns.Single(column => column.Name == "pages");
        Assert.Equal("0", pages.DefaultExpression);
        Assert.False(pages.IsNullable);

        ColumnDefinition createdAt = books.Columns.Single(column => column.Name == "created_at");
        Assert.Equal("timestamp with time zone", createdAt.TypeName);
        Assert.Equal("now()", createdAt.DefaultExpression);

        Assert.Equal(4, books.Constraints.Count);

        ConstraintDefinition foreignKey = books.Constraints.Single(constraint => constraint.Kind is SchemaConstraintKind.ForeignKey);
        Assert.Equal("foreign key (author_id) references authors(id) on delete cascade", foreignKey.Definition);

        ConstraintDefinition check = books.Constraints.Single(constraint => constraint.Kind is SchemaConstraintKind.Check && constraint.Name == "books_title_nonempty");
        Assert.Equal("check (char_length(title) > 0)", check.Definition);

        SequenceDefinition sequence = manifest.Sequences.Single();
        Assert.Equal("docs_id_seq", sequence.Name);
        Assert.Equal("AS bigint START WITH 10 INCREMENT BY 5", sequence.SourceDefinition);

        IndexDefinition plainIndex = manifest.Indexes.Single(index => index.Name == "books_title_idx");
        Assert.Equal("books", plainIndex.TableName);
        Assert.False(plainIndex.IsUnique);
        Assert.Equal("books_title_idx|books|plain|title", plainIndex.Definition);

        IndexDefinition uniqueIndex = manifest.Indexes.Single(index => index.Name == "books_author_title_idx");
        Assert.True(uniqueIndex.IsUnique);
        Assert.Equal("books_author_title_idx|books|unique|author_id, lower(title)", uniqueIndex.Definition);
    }

    /// <summary>
    /// Inline-ограничения в столбцах (PRIMARY KEY, UNIQUE, REFERENCES, CHECK)
    /// преобразуются в табличные ограничения со стандартными именами PostgreSQL.
    /// </summary>
    [Fact]
    public void Parse_InlineColumnConstraints_BecomeTableConstraints()
    {
        const string sql = """
            CREATE TABLE webshelf.items (
                id        bigint NOT NULL PRIMARY KEY,
                code      text   UNIQUE,
                parent_id bigint REFERENCES webshelf.items(id) ON DELETE CASCADE,
                qty       integer NOT NULL DEFAULT 5 CHECK (qty >= 0)
            );
            """;

        SchemaManifest manifest = SchemaSkeletonParser.Parse(sql, Schema);

        TableDefinition table = Assert.Single(manifest.Tables);
        Assert.Equal(4, table.Constraints.Count);

        Assert.Contains(table.Constraints, constraint =>
            constraint.Name == "items_pkey" && constraint.Kind is SchemaConstraintKind.PrimaryKey &&
            constraint.Definition == "primary key (id)");
        Assert.Contains(table.Constraints, constraint =>
            constraint.Name == "items_code_key" && constraint.Kind is SchemaConstraintKind.Unique);
        Assert.Contains(table.Constraints, constraint =>
            constraint.Name == "items_parent_id_fkey" && constraint.Kind is SchemaConstraintKind.ForeignKey &&
            constraint.Definition == "foreign key (parent_id) references items(id) on delete cascade");
        Assert.Contains(table.Constraints, constraint =>
            constraint.Name == "items_qty_check" && constraint.Kind is SchemaConstraintKind.Check);
    }

    /// <summary>
    /// Комментарии (однострочные и блочные) удаляются; точка с запятой внутри
    /// строкового литерала не разрывает оператор.
    /// </summary>
    [Fact]
    public void Parse_CommentsAndSemicolonInString_ParsedCorrectly()
    {
        const string sql = """
            /* блочный
               комментарий */
            CREATE TABLE webshelf.notes (
                body text NOT NULL CHECK (body <> 'знак;точка')
            ); -- хвостовой комментарий
            """;

        SchemaManifest manifest = SchemaSkeletonParser.Parse(sql, Schema);

        TableDefinition table = Assert.Single(manifest.Tables);
        ConstraintDefinition check = Assert.Single(table.Constraints);
        Assert.Equal(SchemaConstraintKind.Check, check.Kind);
        Assert.Equal("check (body <> 'знак;точка')", check.Definition);
    }

    /// <summary>
    /// Каркас без объектов (только схема) даёт пустые списки манифеста.
    /// </summary>
    [Fact]
    public void Parse_SchemaOnly_EmptyManifest()
    {
        SchemaManifest manifest = SchemaSkeletonParser.Parse("CREATE SCHEMA IF NOT EXISTS webshelf;", Schema);

        Assert.Empty(manifest.Tables);
        Assert.Empty(manifest.Sequences);
        Assert.Empty(manifest.Indexes);
    }

    /// <summary>
    /// Неподдерживаемые операторы отклоняются исключением (fail-fast).
    /// </summary>
    [Theory]
    [InlineData("INSERT INTO webshelf.t (a) VALUES (1);")]
    [InlineData("CREATE VIEW webshelf.v AS SELECT 1;")]
    [InlineData("DROP TABLE webshelf.t;")]
    [InlineData("ALTER TABLE webshelf.t DROP COLUMN a;")]
    [InlineData("CREATE FUNCTION webshelf.f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql;")]
    public void Parse_UnsupportedStatement_Throws(string sql)
    {
        Assert.Throws<SchemaSkeletonException>(() => SchemaSkeletonParser.Parse(sql, Schema));
    }

    /// <summary>
    /// Тип serial в каркасе запрещён: требуется явная последовательность.
    /// </summary>
    [Fact]
    public void Parse_SerialType_Throws()
    {
        const string sql = """
            CREATE TABLE webshelf.t (id serial NOT NULL);
            """;

        SchemaSkeletonException exception = Assert.Throws<SchemaSkeletonException>(
            () => SchemaSkeletonParser.Parse(sql, Schema));
        Assert.Contains("serial", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Identity-столбцы (GENERATED) в каркасе запрещены.
    /// </summary>
    [Fact]
    public void Parse_IdentityColumn_Throws()
    {
        const string sql = """
            CREATE TABLE webshelf.t (id bigint GENERATED ALWAYS AS IDENTITY);
            """;

        Assert.Throws<SchemaSkeletonException>(() => SchemaSkeletonParser.Parse(sql, Schema));
    }

    /// <summary>
    /// Повторное объявление таблицы и столбца отклоняется.
    /// </summary>
    [Fact]
    public void Parse_DuplicateTable_Throws()
    {
        const string sql = """
            CREATE TABLE webshelf.t (a int);
            CREATE TABLE webshelf.t (b int);
            """;

        Assert.Throws<SchemaSkeletonException>(() => SchemaSkeletonParser.Parse(sql, Schema));
    }

    /// <summary>
    /// Квалификация схемой, отличной от ожидаемой, отклоняется.
    /// </summary>
    [Fact]
    public void Parse_ForeignSchemaQualification_Throws()
    {
        const string sql = """
            CREATE TABLE public.t (a int);
            """;

        Assert.Throws<SchemaSkeletonException>(() => SchemaSkeletonParser.Parse(sql, Schema));
    }

    /// <summary>
    /// ALTER TABLE … ADD CONSTRAINT для необъявленной таблицы отклоняется.
    /// </summary>
    [Fact]
    public void Parse_AlterForUnknownTable_Throws()
    {
        const string sql = """
            ALTER TABLE webshelf.unknown ADD CONSTRAINT c1 CHECK (a > 0);
            """;

        Assert.Throws<SchemaSkeletonException>(() => SchemaSkeletonParser.Parse(sql, Schema));
    }

    /// <summary>
    /// Загрузчик: отсутствующий файл, хеш содержимого и разбор реального
    /// файла-каркаса поставки (проверяется вместе с копированием в вывод).
    /// </summary>
    [Fact]
    public async Task Loader_MissingFile_ThrowsAndRealSkeletonLoads()
    {
        string missingPath = Path.Combine(Path.GetTempPath(), $"ws_missing_{Guid.NewGuid():N}.sql");
        await Assert.ThrowsAsync<SchemaSkeletonException>(
            () => SchemaSkeletonLoader.LoadAsync(missingPath, Schema, CancellationToken.None));

        string realSkeletonPath = Path.Combine(AppContext.BaseDirectory, "db", "webshelf_skeleton.sql");
        Assert.True(File.Exists(realSkeletonPath), $"Файл каркаса не скопирован в вывод: {realSkeletonPath}");

        SchemaSkeleton skeleton = await SchemaSkeletonLoader.LoadAsync(realSkeletonPath, Schema, CancellationToken.None);

        Assert.Equal(64, skeleton.Sha256Hash.Length);
        Assert.Equal(Schema, skeleton.Manifest.SchemaName);
        Assert.Empty(skeleton.Manifest.Tables);

        string expectedHash = Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(skeleton.SqlText)))
            .ToLowerInvariant();
        Assert.Equal(expectedHash, skeleton.Sha256Hash);
    }
}
