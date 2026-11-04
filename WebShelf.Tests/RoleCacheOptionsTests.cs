using WebShelf.Classes.Security;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты чтения параметров ролевой модели из Server.conf:
/// значения в диапазоне используются как заданы; отсутствующие,
/// нечисловые и вне диапазона (10–300) — заменяются значениями по умолчанию
/// (TTL 60 с, интервал опроса 30 с).
/// </summary>
public class RoleCacheOptionsTests
{
    /// <summary>
    /// Значения в диапазоне 10–300 принимаются как заданные.
    /// </summary>
    [Theory]
    [InlineData(10, 10)]     // нижняя граница
    [InlineData(60, 30)]
    [InlineData(120, 100)]
    [InlineData(300, 300)]   // верхняя граница
    [InlineData(15, 12)]
    public void Create_ValuesInRange_UsedAsIs(int ttl, int poll)
    {
        RoleCacheOptions options = RoleCacheOptions.Create(ttl, poll, out string ttlSource, out string pollSource);

        Assert.Equal(TimeSpan.FromSeconds(ttl), options.CacheTtl);
        Assert.Equal(TimeSpan.FromSeconds(poll), options.PollInterval);
        Assert.Equal("из конфигурации", ttlSource);
        Assert.Equal("из конфигурации", pollSource);
    }

    /// <summary>
    /// TTL вне диапазона (ниже 10 или выше 300) — заменяется 60 с.
    /// </summary>
    [Theory]
    [InlineData(9)]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(301)]
    [InlineData(100000)]
    public void Create_TtlOutOfRange_ReplacedByDefault(int ttl)
    {
        RoleCacheOptions options = RoleCacheOptions.Create(ttl, 30, out string ttlSource, out _);

        Assert.Equal(TimeSpan.FromSeconds(RoleCacheOptions.DefaultTtlSeconds), options.CacheTtl);
        Assert.Contains("вне диапазона", ttlSource);
    }

    /// <summary>
    /// Интервал опроса вне диапазона — заменяется 30 с.
    /// </summary>
    [Theory]
    [InlineData(5)]
    [InlineData(0)]
    [InlineData(500)]
    public void Create_PollOutOfRange_ReplacedByDefault(int poll)
    {
        RoleCacheOptions options = RoleCacheOptions.Create(60, poll, out _, out string pollSource);

        Assert.Equal(TimeSpan.FromSeconds(RoleCacheOptions.DefaultPollIntervalSeconds), options.PollInterval);
        Assert.Contains("вне диапазона", pollSource);
    }

    /// <summary>
    /// Ключи не заданы — значения по умолчанию: TTL 60 с, интервал 30 с.
    /// </summary>
    [Fact]
    public void Create_MissingValues_Defaults()
    {
        RoleCacheOptions options = RoleCacheOptions.Create(null, null, out string ttlSource, out string pollSource);

        Assert.Equal(TimeSpan.FromSeconds(60), options.CacheTtl);
        Assert.Equal(TimeSpan.FromSeconds(30), options.PollInterval);
        Assert.Contains("по умолчанию", ttlSource);
        Assert.Contains("по умолчанию", pollSource);
    }

    /// <summary>
    /// FromTimeSpans переносит интервалы без изменений (для тестов и внутренних нужд).
    /// </summary>
    [Fact]
    public void FromTimeSpans_PassesValuesThrough()
    {
        RoleCacheOptions options = RoleCacheOptions.FromTimeSpans(
            TimeSpan.FromMilliseconds(200),
            TimeSpan.FromMilliseconds(50));

        Assert.Equal(TimeSpan.FromMilliseconds(200), options.CacheTtl);
        Assert.Equal(TimeSpan.FromMilliseconds(50), options.PollInterval);
    }
}
