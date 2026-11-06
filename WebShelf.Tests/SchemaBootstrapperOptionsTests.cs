using WebShelf.Classes.DB;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты разбора параметров сервисной инфраструктуры БД из словаря конфигурации
/// <see cref="SchemaBootstrapperOptions.TryCreate"/>: значения по умолчанию,
/// пользовательские значения и защитные отказы (имя схемы, каталог дампов
/// внутри wwwroot, некорректные значения).
/// </summary>
public class SchemaBootstrapperOptionsTests
{
    /// <summary>Пустая конфигурация даёт безопасные значения по умолчанию.</summary>
    [Fact]
    public void TryCreate_EmptyConfig_SafeDefaults()
    {
        SchemaBootstrapperOptions? options = SchemaBootstrapperOptions.TryCreate([]);

        Assert.NotNull(options);
        Assert.Equal("webshelf", options.SchemaName);
        Assert.Equal(90, options.DumpRetentionDays);
        Assert.False(options.AutoSchemaReset);
        Assert.Equal(
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "db", "webshelf_skeleton.sql")),
            options.SkeletonPath);
        Assert.Equal(
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Data", "DbDumps")),
            options.DumpsDirectory);
    }

    /// <summary>Корректные пользовательские значения применяются (включая абсолютные пути).</summary>
    [Fact]
    public void TryCreate_CustomValues_Applied()
    {
        string absoluteSkeleton = Path.Combine(Path.GetTempPath(), "skeleton.sql");

        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            ["dbschema"] = "shelf_data",
            ["dbskeletonpath"] = absoluteSkeleton,
            ["dbdumpspath"] = "Dumps/Custom",
            ["dbdumpretentiondays"] = "30",
            ["dbautoschemareset"] = "true",
        };

        SchemaBootstrapperOptions? options = SchemaBootstrapperOptions.TryCreate(config);

        Assert.NotNull(options);
        Assert.Equal("shelf_data", options.SchemaName);
        Assert.Equal(absoluteSkeleton, options.SkeletonPath);
        Assert.Equal(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Dumps", "Custom")), options.DumpsDirectory);
        Assert.Equal(30, options.DumpRetentionDays);
        Assert.True(options.AutoSchemaReset);
    }

    /// <summary>Некорректное имя схемы — отказ (конфигурация не загружается).</summary>
    [Theory]
    [InlineData("WebShelf")]
    [InlineData("1schema")]
    [InlineData("schema-name")]
    [InlineData("schema name")]
    [InlineData("public; DROP TABLE x")]
    public void TryCreate_InvalidSchemaName_ReturnsNull(string schemaValue)
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            ["dbschema"] = schemaValue,
        };

        Assert.Null(SchemaBootstrapperOptions.TryCreate(config));
    }

    /// <summary>Каталог дампов внутри wwwroot — отказ (дампы недоступны по web).</summary>
    [Fact]
    public void TryCreate_DumpsPathInsideWwwroot_ReturnsNull()
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            ["dbdumpspath"] = "wwwroot/dumps",
        };

        Assert.Null(SchemaBootstrapperOptions.TryCreate(config));
    }

    /// <summary>Некорректный срок хранения заменяется значением по умолчанию.</summary>
    [Theory]
    [InlineData("abc")]
    [InlineData("0")]
    [InlineData("-5")]
    [InlineData("999999")]
    public void TryCreate_InvalidRetentionDays_DefaultUsed(string retentionValue)
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            ["dbdumpretentiondays"] = retentionValue,
        };

        SchemaBootstrapperOptions? options = SchemaBootstrapperOptions.TryCreate(config);

        Assert.NotNull(options);
        Assert.Equal(90, options.DumpRetentionDays);
    }

    /// <summary>Некорректное значение автосброса заменяется безопасным false.</summary>
    [Theory]
    [InlineData("yes")]
    [InlineData("1")]
    [InlineData("включено")]
    public void TryCreate_InvalidAutoReset_SafeFalse(string autoResetValue)
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            ["dbautoschemareset"] = autoResetValue,
        };

        SchemaBootstrapperOptions? options = SchemaBootstrapperOptions.TryCreate(config);

        Assert.NotNull(options);
        Assert.False(options.AutoSchemaReset);
    }

    /// <summary>Значения автосброса true/false (без учёта регистра) разбираются точно.</summary>
    [Theory]
    [InlineData("true", true)]
    [InlineData("TRUE", true)]
    [InlineData("False", false)]
    [InlineData("false", false)]
    public void TryCreate_ValidAutoReset_Parsed(string autoResetValue, bool expected)
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            ["dbautoschemareset"] = autoResetValue,
        };

        SchemaBootstrapperOptions? options = SchemaBootstrapperOptions.TryCreate(config);

        Assert.NotNull(options);
        Assert.Equal(expected, options.AutoSchemaReset);
    }
}
