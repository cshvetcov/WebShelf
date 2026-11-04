using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Characterization-тесты парсера Server.conf (<see cref="Data.ReadConfigFile"/>,
/// шаг 0 дорожной карты декомпозиции). Фиксируют фактическое поведение
/// разбора key=value до выноса парсера в отдельный класс (шаг 5):
/// ни одно ожидание здесь не является «правильным по замыслу» — все они
/// сняты с текущей реализации. Тесты платформонезависимы (DPAPI не требуется),
/// работают с уникальными временными файлами и не меняют конфигурацию.
/// </summary>
public class DataConfigParserTests
{
    /// <summary>
    /// Возвращает парсер-обёртку над тестируемым методом: парсер принимает
    /// путь явно и не зависит от пути, внедрённого в конструктор Data.
    /// </summary>
    private static Dictionary<string, string> ParseFile(string path)
    {
        Data data = new Data();

        return data.ReadConfigFile(path);
    }

    /// <summary>
    /// Простейшие строки key=value разбираются в словарь.
    /// </summary>
    [Fact]
    public void ReadConfigFile_KeyValueLines_ParsedToDictionary()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "scheme=http",
                "port=38080");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Equal(2, config.Count);
            Assert.Equal("http", config["scheme"]);
            Assert.Equal("38080", config["port"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Строки-комментарии (первый символ # после обрезки пробелов) пропускаются.
    /// </summary>
    [Fact]
    public void ReadConfigFile_CommentLines_Skipped()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "# Настройки схемы",
                "scheme=http",
                "   # комментарий с ведущими пробелами",
                "#port=закомментированный ключ");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Single(config);
            Assert.Equal("http", config["scheme"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Пустые строки и строки из одних пробелов/табуляций пропускаются.
    /// </summary>
    [Fact]
    public void ReadConfigFile_EmptyAndWhitespaceLines_Skipped()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "",
                "   ",
                "\t",
                "scheme=http");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Single(config);
            Assert.Equal("http", config["scheme"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Пробелы вокруг ключа и значения обрезаются.
    /// </summary>
    [Fact]
    public void ReadConfigFile_SpacesAroundKeyAndValue_Trimmed()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "   scheme   =   http   ",
                "  domainname\t=\tcontoso.local  ");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Equal("http", config["scheme"]);
            Assert.Equal("contoso.local", config["domainname"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Строки без знака равенства пропускаются как некорректные.
    /// </summary>
    [Theory]
    [InlineData("просто текст без знака равенства")]
    [InlineData("localhost:5432")]
    public void ReadConfigFile_LinesWithoutEqualsSign_Skipped(string malformedLine)
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                malformedLine,
                "scheme=http");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Single(config);
            Assert.Equal("http", config["scheme"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Строка, начинающаяся со знака равенства (пустой ключ), пропускается.
    /// </summary>
    [Fact]
    public void ReadConfigFile_EmptyKeyLine_Skipped()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "=значение без ключа",
                "scheme=http");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Single(config);
            Assert.Equal("http", config["scheme"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// При дубликатах ключей побеждает последнее значение
    /// (в соответствии с комментарием в реализации).
    /// </summary>
    [Fact]
    public void ReadConfigFile_DuplicateKeys_LastValueWins()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "port=11111",
                "port=22222",
                "port=38080");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Single(config);
            Assert.Equal("38080", config["port"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Ключи словаря регистронезависимы (OrdinalIgnoreCase): ключи,
    /// отличающиеся только регистром, являются одним и тем же ключом.
    /// </summary>
    [Fact]
    public void ReadConfigFile_Keys_CaseInsensitiveOrdinal()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "Scheme=http",
                "DOMAINNAME=contoso.local");

            Dictionary<string, string> config = ParseFile(path);

            // Обращение по ключу в другом регистре находит значение
            Assert.Equal("http", config["scheme"]);
            Assert.Equal("contoso.local", config["domainname"]);

            // Различие регистра — это дубликат: побеждает последнее значение
            string path2 = Path.Combine(directory, "Server2.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path2,
                "SCHEME=https",
                "scheme=http");
            Dictionary<string, string> config2 = ParseFile(path2);

            Assert.Single(config2);
            Assert.Equal("http", config2["scheme"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Кириллица в значениях читается корректно (UTF-8 без BOM).
    /// </summary>
    [Fact]
    public void ReadConfigFile_Utf8CyrillicValue_Preserved()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "domainname=ТестовыйДомен.local",
                "scheme=http");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Equal("ТестовыйДомен.local", config["domainname"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// BOM в начале файла не загрязняет первый ключ: StreamReader
    /// распознаёт и отрезает метку порядка байтов.
    /// </summary>
    [Fact]
    public void ReadConfigFile_BomAtFileStart_FirstKeyClean()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8WithBom(path,
                "domainname=contoso.local",
                "scheme=http");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Equal(2, config.Count);
            Assert.Equal("contoso.local", config["domainname"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Значение может содержать знак равенства: разбиение идёт
    /// по первому вхождению.
    /// </summary>
    [Fact]
    public void ReadConfigFile_ValueWithEqualsSign_Preserved()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "dbhost=postgres://user@host:5432/db?sslmode=require");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Equal("postgres://user@host:5432/db?sslmode=require", config["dbhost"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Пустое значение допустимо: ключ попадает в словарь со значением "".
    /// Так парсер различает «ключа нет» и «ключ есть, но пустой».
    /// </summary>
    [Fact]
    public void ReadConfigFile_EmptyValue_KeyPresentWithEmptyString()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "domainuser=",
                "scheme=http");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Equal(2, config.Count);
            Assert.True(config.TryGetValue("domainuser", out string? value));
            Assert.Equal(string.Empty, value);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Символ # внутри значения (не в начале строки) — часть значения,
    /// а не начало комментария: парсер различает только строки,
    /// начинающиеся с #.
    /// </summary>
    [Fact]
    public void ReadConfigFile_InlineHash_IsPartOfValue()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "dbname=webshelf # рабочая база");

            Dictionary<string, string> config = ParseFile(path);

            Assert.Equal("webshelf # рабочая база", config["dbname"]);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Отсутствующий файл — ошибка чтения пробрасывается наружу
    /// (после журналирования), а не проглатывается: вызывающий
    /// <see cref="Data.ReadConfigAsync"/> перехватывает её своим catch-блоком.
    /// </summary>
    [Fact]
    public void ReadConfigFile_MissingFile_ThrowsIOException()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");

            Assert.ThrowsAny<IOException>(() => ParseFile(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
