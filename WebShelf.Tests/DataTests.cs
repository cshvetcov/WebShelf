using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты хранилища системных данных Data: жизненный цикл InstanceId,
/// свойство InstanceIdShort и отказные сценарии чтения конфигурации.
/// </summary>
public class DataTests
{
    /// <summary>Имя файла конфигурации, ожидаемое рядом с бинарниками приложения.</summary>
    private static string ConfigFilePath =>
        Path.Combine(AppContext.BaseDirectory, "Server.conf");

    /// <summary>
    /// Обращение к InstanceId до установки значения выбрасывает InvalidOperationException.
    /// </summary>
    [Fact]
    public void InstanceId_BeforeInitialization_ThrowsInvalidOperationException()
    {
        Data data = new Data();

        Assert.Throws<InvalidOperationException>(() => _ = data.InstanceId);
    }

    /// <summary>
    /// SetInstanceId сохраняет переданное значение (с обрезкой пробелов).
    /// </summary>
    [Theory]
    [InlineData("0123456789ABCDEFGHIJKLMNO", "0123456789ABCDEFGHIJKLMNO")]
    [InlineData("  ABCDEFGHIJKLMNOPQRSTUVWXY  ", "ABCDEFGHIJKLMNOPQRSTUVWXY")]
    public void SetInstanceId_ValidValue_SetsTrimmedValue(string value, string expected)
    {
        Data data = new Data();

        data.SetInstanceId(value);

        Assert.Equal(expected, data.InstanceId);
    }

    /// <summary>
    /// SetInstanceId отклоняет пустые значения.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SetInstanceId_EmptyValue_ThrowsArgumentException(string? value)
    {
        Data data = new Data();

        Assert.Throws<ArgumentException>(() => data.SetInstanceId(value!));
    }

    /// <summary>
    /// Повторный вызов SetInstanceId запрещён: значение write-once
    /// на весь срок жизни процесса.
    /// </summary>
    [Fact]
    public void SetInstanceId_SecondCall_ThrowsInvalidOperationException()
    {
        Data data = new Data();
        data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");

        Assert.Throws<InvalidOperationException>(() =>
            data.SetInstanceId("ZYXWVUTSRQPONMLKJIHGFEDCBA"));
    }

    /// <summary>
    /// InstanceIdShort для полного ULID возвращает первые 12 символов в нижнем регистре.
    /// </summary>
    [Fact]
    public void InstanceIdShort_FullUlid_ReturnsFirst12Lowercase()
    {
        Data data = new Data();
        data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");

        Assert.Equal("0123456789ab", data.InstanceIdShort);
    }

    /// <summary>
    /// InstanceIdShort для значения короче 12 символов возвращает всё значение
    /// в нижнем регистре.
    /// </summary>
    [Fact]
    public void InstanceIdShort_ShortValue_ReturnsWholeValueLowercase()
    {
        Data data = new Data();
        data.SetInstanceId("ABCDEF");

        Assert.Equal("abcdef", data.InstanceIdShort);
    }

    /// <summary>
    /// TLS-сертификат отсутствует до чтения конфигурации.
    /// </summary>
    [Fact]
    public void TlsCertificate_BeforeInitialization_IsNull()
    {
        Data data = new Data();

        Assert.Null(data.TlsCertificate);
    }

    /// <summary>
    /// Чтение конфигурации без установленного InstanceId завершается отказом.
    /// </summary>
    [Fact]
    public async Task ReadConfigAsync_WithoutInstanceId_ReturnsFalse()
    {
        Data data = new Data();

        bool result = await data.ReadConfigAsync();

        Assert.False(result);
    }

    /// <summary>
    /// Отсутствующий файл Server.conf завершает чтение конфигурации отказом.
    /// Тест пропускается, если в выходном каталоге тестов неожиданно оказался
    /// настоящий Server.conf.
    /// </summary>
    [Fact]
    public async Task ReadConfigAsync_MissingConfigFile_ReturnsFalse()
    {
        Assert.SkipWhen(File.Exists(ConfigFilePath),
            $"В выходном каталоге тестов присутствует {ConfigFilePath} — сценарий неприменим.");

        Data data = new Data();
        data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");

        bool result = await data.ReadConfigAsync();

        Assert.False(result);
    }
}
