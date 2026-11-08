using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты разбора параметров инфраструктуры согласия на обработку файлов
/// cookie из словаря конфигурации (<see cref="CookieConsentOptions.Create"/>):
/// безопасное значение по умолчанию, включение баннера, нечувствительность
/// к регистру ключа и значения, реакция на некорректные значения и отказ
/// на null-словаре; инициализация опции при чтении Server.conf на уровне
/// <see cref="Data.ReadConfigAsync"/>.
/// </summary>
public class CookieConsentOptionsTests
{
    /// <summary>Пустая конфигурация даёт безопасное значение: баннер выключен.</summary>
    [Fact]
    public void Create_EmptyConfig_BannerDisabled()
    {
        CookieConsentOptions options = CookieConsentOptions.Create([]);

        Assert.False(options.BannerEnabled);
    }

    /// <summary>Отсутствие ключа — как пустая конфигурация: баннер выключен.</summary>
    [Theory]
    [InlineData("scheme", "https")]
    [InlineData("port", "38080")]
    public void Create_NoConsentKey_BannerDisabled(string key, string value)
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            [key] = value
        };

        CookieConsentOptions options = CookieConsentOptions.Create(config);

        Assert.False(options.BannerEnabled);
    }

    /// <summary>Значение true включает баннер согласия.</summary>
    [Fact]
    public void Create_TrueValue_BannerEnabled()
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            ["cookieconsent"] = "true"
        };

        CookieConsentOptions options = CookieConsentOptions.Create(config);

        Assert.True(options.BannerEnabled);
    }

    /// <summary>Значение false — безопасное: баннер выключен.</summary>
    [Fact]
    public void Create_FalseValue_BannerDisabled()
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            ["cookieconsent"] = "false"
        };

        CookieConsentOptions options = CookieConsentOptions.Create(config);

        Assert.False(options.BannerEnabled);
    }

    /// <summary>Ключ ищется без учёта регистра (парсер Server.conf).</summary>
    [Theory]
    [InlineData("COOKIECONSENT")]
    [InlineData("CookieConsent")]
    [InlineData("cookieCONSENT")]
    public void Create_KeyCaseInsensitive_BannerEnabled(string key)
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            [key] = "true"
        };

        CookieConsentOptions options = CookieConsentOptions.Create(config);

        Assert.True(options.BannerEnabled);
    }

    /// <summary>Значение разбирается bool.TryParse: регистр и пробелы не важны.</summary>
    [Theory]
    [InlineData("True")]
    [InlineData("TRUE")]
    [InlineData("  true  ")]
    public void Create_ValueCaseAndSpaces_Parsed(string value)
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            ["cookieconsent"] = value
        };

        CookieConsentOptions options = CookieConsentOptions.Create(config);

        Assert.True(options.BannerEnabled);
    }

    /// <summary>Некорректное значение заменяется безопасным false (баннер выключен).</summary>
    [Theory]
    [InlineData("yes")]
    [InlineData("1")]
    [InlineData("on")]
    [InlineData("да")]
    [InlineData("включить")]
    public void Create_InvalidValue_BannerDisabled(string value)
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            ["cookieconsent"] = value
        };

        CookieConsentOptions options = CookieConsentOptions.Create(config);

        Assert.False(options.BannerEnabled);
    }

    /// <summary>Пустое или пробельное значение — как отсутствие ключа.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void Create_WhitespaceValue_BannerDisabled(string value)
    {
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
        {
            ["cookieconsent"] = value
        };

        CookieConsentOptions options = CookieConsentOptions.Create(config);

        Assert.False(options.BannerEnabled);
    }

    /// <summary>Null-словарь — исключение аргумента (контракт метода).</summary>
    [Fact]
    public void Create_NullConfig_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CookieConsentOptions.Create(null!));
    }

    /// <summary>
    /// Опция инициализируется при чтении Server.conf на уровне Data:
    /// ключ cookieconsent=true применяется даже когда конфигурация в целом
    /// не загружается (тестовый домен .invalid недоступен) — инициализация
    /// скалярных секций выполняется до агрегатной проверки результата.
    /// </summary>
    [Fact]
    public async Task ReadConfigAsync_CookieConsentTrue_OptionsInitialized()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "domainname=webshelf-test.invalid",
                "scheme=http",
                "port=38080",
                "cookieconsent=true");

            Data data = DataConfigTestHelpers.CreateData(path);
            data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");

            bool result = await data.ReadConfigAsync();

            // Домен недоступен — конфигурация в целом не загружена,
            // но скалярные секции (включая cookieconsent) инициализированы
            Assert.False(result);
            Assert.NotNull(data.CookieConsentOptions);
            Assert.True(data.CookieConsentOptions.BannerEnabled);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
