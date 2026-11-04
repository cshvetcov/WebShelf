using WebShelf.Classes.Security;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты кэша роли RoleCache с управляемым источником времени: попадание
/// внутри TTL, истечение записи, чтение последней известной роли (TryPeek)
/// и удаление записи.
/// </summary>
public class RoleCacheTests
{
    /// <summary>
    /// Создаёт кэш с фиктивными часами: время задаётся и продвигается тестом.
    /// </summary>
    private static (RoleCache Cache, FakeClock Clock) CreateCache(TimeSpan ttl)
    {
        FakeClock clock = new FakeClock();
        RoleCache cache = new RoleCache(ttl, clock.UtcNow);

        return (cache, clock);
    }

    [Fact]
    public void Set_ThenTryGet_WithinTtl_ReturnsValue()
    {
        (RoleCache cache, FakeClock clock) = CreateCache(TimeSpan.FromSeconds(60));
        RoleResolution resolution = RoleCatalog.ResolveFromRoles([RoleCatalog.Executor]);

        cache.Set("ivanov", resolution);

        // Время внутри TTL — запись актуальна
        clock.Advance(TimeSpan.FromSeconds(59));
        Assert.True(cache.TryGet("ivanov", out RoleResolution cached));
        Assert.Equal(resolution, cached);
    }

    [Fact]
    public void TryGet_AfterTtlExpired_ReturnsFalse()
    {
        (RoleCache cache, FakeClock clock) = CreateCache(TimeSpan.FromSeconds(60));
        cache.Set("ivanov", RoleCatalog.ResolveFromRoles([RoleCatalog.Executor]));

        clock.Advance(TimeSpan.FromSeconds(61));

        Assert.False(cache.TryGet("ivanov", out _));
    }

    [Fact]
    public void TryGet_AtExactTtlBoundary_ReturnsFalse()
    {
        // TTL — предельный срок жизни: ровно через TTL запись уже устарела
        (RoleCache cache, FakeClock clock) = CreateCache(TimeSpan.FromSeconds(60));
        cache.Set("ivanov", RoleCatalog.ResolveFromRoles([RoleCatalog.Executor]));

        clock.Advance(TimeSpan.FromSeconds(60));

        Assert.False(cache.TryGet("ivanov", out _));
    }

    [Fact]
    public void TryGet_UnknownUser_ReturnsFalse()
    {
        (RoleCache cache, _) = CreateCache(TimeSpan.FromSeconds(60));

        Assert.False(cache.TryGet("petrov", out _));
    }

    [Fact]
    public void TryPeek_ReturnsExpiredValue()
    {
        // TryPeek используется для сравнения с новым результатом: последняя
        // известная роль нужна даже после истечения TTL
        (RoleCache cache, FakeClock clock) = CreateCache(TimeSpan.FromSeconds(60));
        RoleResolution resolution = RoleCatalog.ResolveFromRoles([RoleCatalog.Director]);
        cache.Set("ivanov", resolution);

        clock.Advance(TimeSpan.FromSeconds(120));

        Assert.False(cache.TryGet("ivanov", out _));
        Assert.True(cache.TryPeek("ivanov", out RoleResolution lastKnown));
        Assert.Equal(resolution, lastKnown);
    }

    [Fact]
    public void Set_OverwritesPreviousValue()
    {
        (RoleCache cache, FakeClock _) = CreateCache(TimeSpan.FromSeconds(60));

        cache.Set("ivanov", RoleCatalog.ResolveFromRoles([RoleCatalog.Executor]));
        cache.Set("ivanov", RoleCatalog.ResolveFromRoles([RoleCatalog.Manager]));

        Assert.True(cache.TryGet("ivanov", out RoleResolution cached));
        Assert.Equal(AppRoleId.Manager, cached.EffectiveRole.Id);
    }

    [Fact]
    public void TryGet_KeyIsCaseInsensitive()
    {
        // sAMAccountName в AD регистронезависим: IVANOV и ivanov — один пользователь
        (RoleCache cache, FakeClock _) = CreateCache(TimeSpan.FromSeconds(60));
        cache.Set("IVANOV", RoleCatalog.ResolveFromRoles([RoleCatalog.Gip]));

        Assert.True(cache.TryGet("ivanov", out RoleResolution cached));
        Assert.Equal(AppRoleId.Gip, cached.EffectiveRole.Id);
    }

    [Fact]
    public void Remove_ExistingEntry_ReturnsTrueAndClearsIt()
    {
        (RoleCache cache, FakeClock _) = CreateCache(TimeSpan.FromSeconds(60));
        cache.Set("ivanov", RoleCatalog.ResolveFromRoles([RoleCatalog.Executor]));

        Assert.True(cache.Remove("ivanov"));
        Assert.False(cache.TryPeek("ivanov", out _));
        Assert.False(cache.Remove("ivanov"));
    }

    [Fact]
    public void Constructor_NonPositiveTtl_ThrowsArgumentOutOfRangeException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RoleCache(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RoleCache(TimeSpan.FromSeconds(-1)));
    }

    [Fact]
    public void Set_NullResolution_ThrowsArgumentNullException()
    {
        (RoleCache cache, FakeClock _) = CreateCache(TimeSpan.FromSeconds(60));

        Assert.Throws<ArgumentNullException>(() => cache.Set("ivanov", null!));
    }

    /// <summary>
    /// Фиктивные часы для кэша: тест управляет временем напрямую, без реальных задержек.
    /// </summary>
    private sealed class FakeClock
    {
        private DateTimeOffset _now = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

        /// <summary>
        /// Функция текущего времени для передачи в RoleCache.
        /// </summary>
        internal Func<DateTimeOffset> UtcNow => () => _now;

        /// <summary>
        /// Продвигает время вперёд.
        /// </summary>
        /// <param name="delta">Интервал продвижения.</param>
        internal void Advance(TimeSpan delta) => _now = _now.Add(delta);
    }
}
