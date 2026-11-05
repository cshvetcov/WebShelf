using WebShelf.Classes.Security;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты резолвера ролей: вычисление по прямым группам, старшинство,
/// TTL-кэш (вариант 1), свежее вычисление (вариант 3), stale-if-error.
/// Домен подменяется FakeAdGroupSource (наследники IAdGroupSource в DomainTests
/// не задействованы: живой AD в тестах недоступен).
/// </summary>
public class RoleResolverTests
{
    /// <summary>Фиксированный InstanceIdShort, как в подмене источника групп.</summary>
    private const string Id = RoleTestFakes.InstanceShort;

    private static RoleResolver CreateResolver(
        RoleTestFakes.FakeAdGroupSource ad,
        RoleTestFakes.FakeTimeProvider time,
        int ttlSeconds = 30)
    {
        RoleCacheOptions options = RoleCacheOptions.FromTimeSpans(
            TimeSpan.FromSeconds(ttlSeconds),
            TimeSpan.FromSeconds(10));

        return new RoleResolver(ad, options, time);
    }

    /// <summary>
    /// Пользователь в нескольких ролевых группах: действует старшая роль,
    /// список совпавших ролей — по возрастанию старшинства.
    /// </summary>
    [Fact]
    public void Resolve_MultipleRoles_SeniorWins()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        ad.SetUserGroups("ivanov",
            $"WebShelf-{Id}-Users",
            $"WebShelf-{Id}-Executor",
            $"WebShelf-{Id}-Manager",
            $"WebShelf-{Id}-GIP");
        RoleResolver resolver = CreateResolver(ad, new RoleTestFakes.FakeTimeProvider());

        RoleResolution? result = resolver.Resolve("ivanov");

        Assert.NotNull(result);
        Assert.True(result.HasUsersGroup);
        Assert.Same(RoleCatalog.Manager, result.EffectiveRole);
        Assert.Equal(
            ["Manager", "GIP", "Executor"],
            [.. result.MatchedRoles.Select(role => role.SystemName)]);
    }

    /// <summary>
    /// Пользователь без ролевых групп (только Users) — Гость.
    /// </summary>
    [Fact]
    public void Resolve_NoRoleGroups_Guest()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users");
        RoleResolver resolver = CreateResolver(ad, new RoleTestFakes.FakeTimeProvider());

        RoleResolution? result = resolver.Resolve("ivanov");

        Assert.NotNull(result);
        Assert.True(result.HasUsersGroup);
        Assert.Same(RoleCatalog.Guest, result.EffectiveRole);
        Assert.Empty(result.MatchedRoles);
    }

    /// <summary>
    /// Пользователь удалён из AD (пустой список групп): Гость без Users.
    /// </summary>
    [Fact]
    public void Resolve_UserRemovedFromAd_GuestWithoutUsers()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        // Группы не заданы — GetUserGroupNames вернёт пустой список
        RoleResolver resolver = CreateResolver(ad, new RoleTestFakes.FakeTimeProvider());

        RoleResolution? result = resolver.Resolve("ivanov");

        Assert.NotNull(result);
        Assert.False(result.HasUsersGroup);
        Assert.Same(RoleCatalog.Guest, result.EffectiveRole);
    }

    /// <summary>
    /// В пределах TTL повторное вычисление не обращается к AD.
    /// </summary>
    [Fact]
    public void Resolve_WithinTtl_NoExtraAdCalls()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-Manager");
        RoleTestFakes.FakeTimeProvider time = new();
        RoleResolver resolver = CreateResolver(ad, time, ttlSeconds: 30);

        resolver.Resolve("ivanov");
        RoleResolution? second = resolver.Resolve("ivanov");

        Assert.Equal(1, ad.GetUserGroupNamesCalls);
        Assert.NotNull(second);
        Assert.Same(RoleCatalog.Manager, second.EffectiveRole);
    }

    /// <summary>
    /// После истечения TTL — свежее вычисление с обновлением кэша.
    /// </summary>
    [Fact]
    public void Resolve_AfterTtlExpired_Recalculates()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-Manager");
        RoleTestFakes.FakeTimeProvider time = new();
        RoleResolver resolver = CreateResolver(ad, time, ttlSeconds: 30);

        resolver.Resolve("ivanov");

        // Группы изменились: менеджер повышен до директора
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-Director");
        time.Advance(TimeSpan.FromSeconds(31));

        RoleResolution? fresh = resolver.Resolve("ivanov");

        Assert.Equal(2, ad.GetUserGroupNamesCalls);
        Assert.NotNull(fresh);
        Assert.Same(RoleCatalog.Director, fresh.EffectiveRole);
    }

    /// <summary>
    /// Сбой AD при непустом кэше: возвращается последнее известное значение (stale-if-error).
    /// </summary>
    [Fact]
    public void Resolve_AdUnavailableWithCache_ReturnsStaleValue()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-Manager");
        RoleTestFakes.FakeTimeProvider time = new();
        RoleResolver resolver = CreateResolver(ad, time, ttlSeconds: 30);

        resolver.Resolve("ivanov");

        ad.AdUnavailable = true;
        time.Advance(TimeSpan.FromSeconds(31));

        RoleResolution? stale = resolver.Resolve("ivanov");

        Assert.NotNull(stale);
        Assert.Same(RoleCatalog.Manager, stale.EffectiveRole);
    }

    /// <summary>
    /// Сбой AD без кэша — null (вход в этом случае отклоняется: fail-secure).
    /// </summary>
    [Fact]
    public void Resolve_AdUnavailableWithoutCache_ReturnsNull()
    {
        RoleTestFakes.FakeAdGroupSource ad = new() { AdUnavailable = true };
        RoleResolver resolver = CreateResolver(ad, new RoleTestFakes.FakeTimeProvider());

        Assert.Null(resolver.Resolve("ivanov"));
    }

    /// <summary>
    /// Пустое имя пользователя — null без обращения к AD.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Resolve_EmptyUsername_ReturnsNull(string? username)
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        RoleResolver resolver = CreateResolver(ad, new RoleTestFakes.FakeTimeProvider());

        Assert.Null(resolver.Resolve(username!));
        Assert.Equal(0, ad.GetUserGroupNamesCalls);
    }

    /// <summary>
    /// ResolveFresh обходит кэш и обновляет его результатом.
    /// </summary>
    [Fact]
    public void ResolveFresh_BypassesCache_UpdatesIt()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-Executor");
        RoleTestFakes.FakeTimeProvider time = new();
        RoleResolver resolver = CreateResolver(ad, time, ttlSeconds: 300);

        RoleResolution? first = resolver.ResolveFresh("ivanov");
        Assert.Same(RoleCatalog.Executor, first?.EffectiveRole);

        // Смена роли до истечения TTL: ResolveFresh обязан увидеть её сразу
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-GIP");
        RoleResolution? fresh = resolver.ResolveFresh("ivanov");

        Assert.Same(RoleCatalog.Gip, fresh?.EffectiveRole);

        // И кэш теперь хранит свежее значение
        Assert.Same(RoleCatalog.Gip, resolver.Peek("ivanov")?.EffectiveRole);
    }

    /// <summary>
    /// ResolveFresh при сбое AD — null; кэш не затрагивается.
    /// </summary>
    [Fact]
    public void ResolveFresh_AdUnavailable_CacheUntouched()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-Manager");
        RoleTestFakes.FakeTimeProvider time = new();
        RoleResolver resolver = CreateResolver(ad, time, ttlSeconds: 30);

        resolver.Resolve("ivanov");
        ad.AdUnavailable = true;

        Assert.Null(resolver.ResolveFresh("ivanov"));
        Assert.Same(RoleCatalog.Manager, resolver.Peek("ivanov")?.EffectiveRole);
    }

    /// <summary>
    /// Peek возвращает значение без пересчёта; GetTrackedUsernames — ключи кэша.
    /// </summary>
    [Fact]
    public void Peek_And_GetTrackedUsernames()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-Manager");
        ad.SetUserGroups("petrov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-Executor");
        RoleResolver resolver = CreateResolver(ad, new RoleTestFakes.FakeTimeProvider());

        resolver.Resolve("ivanov");
        resolver.Resolve("petrov");

        Assert.Equal(2, resolver.GetTrackedUsernames().Count);
        Assert.Contains("ivanov", resolver.GetTrackedUsernames());
        Assert.Contains("petrov", resolver.GetTrackedUsernames());
        Assert.Null(resolver.Peek("sidorov"));
    }

    /// <summary>
    /// Ключ кэша не зависит от регистра имени: Ivanov и ivanov — один пользователь.
    /// </summary>
    [Fact]
    public void Resolve_UsernameCaseInsensitive()
    {
        RoleTestFakes.FakeAdGroupSource ad = new();
        ad.SetUserGroups("ivanov", $"WebShelf-{Id}-Users", $"WebShelf-{Id}-Manager");
        RoleResolver resolver = CreateResolver(ad, new RoleTestFakes.FakeTimeProvider());

        resolver.Resolve("ivanov");
        RoleResolution? second = resolver.Resolve("IVANOV");

        Assert.Equal(1, ad.GetUserGroupNamesCalls);
        Assert.Same(RoleCatalog.Manager, second?.EffectiveRole);
    }
}
