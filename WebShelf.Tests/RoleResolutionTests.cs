using WebShelf.Classes.Security;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты результата вычисления ролей RoleResolution: эквивалентность
/// (сравнение результатов используется для обнаружения изменения роли),
/// признак Гостя и порядок назначенных ролей.
/// </summary>
public class RoleResolutionTests
{
    #region Эквивалентность

    [Fact]
    public void Equals_SameRoles_ReturnsTrue()
    {
        RoleResolution first = RoleCatalog.ResolveFromRoles([RoleCatalog.Manager, RoleCatalog.Gip]);
        RoleResolution second = RoleCatalog.ResolveFromRoles([RoleCatalog.Gip, RoleCatalog.Manager]);

        // Одинаковый набор ролей (в любом порядке на входе) — эквивалентные результаты
        Assert.Equal(first, second);
        Assert.True(first.Equals(second));
        Assert.Equal(first.GetHashCode(), second.GetHashCode());
    }

    [Fact]
    public void Equals_SameGuests_ReturnsTrue()
    {
        RoleResolution first = RoleCatalog.ResolveFromRoles([]);
        RoleResolution second = RoleCatalog.ResolveFromGroupNames(["Domain Users", "WebShelf-000000000000-Users"], "000000000000");

        Assert.Equal(first, second);
    }

    [Fact]
    public void Equals_DifferentEffectiveRole_ReturnsFalse()
    {
        RoleResolution manager = RoleCatalog.ResolveFromRoles([RoleCatalog.Manager]);
        RoleResolution director = RoleCatalog.ResolveFromRoles([RoleCatalog.Director]);

        Assert.NotEqual(manager, director);
    }

    [Fact]
    public void Equals_DifferentMatchedSet_ReturnsFalse()
    {
        // Действующая роль одинаковая, но состав назначенных ролей различается
        RoleResolution onlyManager = RoleCatalog.ResolveFromRoles([RoleCatalog.Manager]);
        RoleResolution managerAndGip = RoleCatalog.ResolveFromRoles([RoleCatalog.Manager, RoleCatalog.Gip]);

        Assert.NotEqual(onlyManager, managerAndGip);
    }

    [Fact]
    public void Equals_NullAndOtherType_ReturnsFalse()
    {
        RoleResolution resolution = RoleCatalog.ResolveFromRoles([RoleCatalog.Executor]);

        Assert.False(resolution.Equals(null));
        Assert.False(resolution.Equals("Executor"));
    }

    #endregion

    #region Гость и порядок ролей

    [Fact]
    public void IsGuest_GuestResolution_ReturnsTrue()
    {
        RoleResolution resolution = RoleCatalog.ResolveFromRoles([]);

        Assert.True(resolution.IsGuest);
        Assert.Equal("Guest", resolution.EffectiveRole.SystemName);
        Assert.Equal("Гость", resolution.EffectiveRole.DisplayName);
    }

    [Fact]
    public void EffectiveRole_IsFirstMatchedBySeniority()
    {
        RoleResolution resolution = RoleCatalog.ResolveFromRoles([RoleCatalog.Executor, RoleCatalog.BimManager]);

        Assert.Equal(RoleCatalog.BimManager, resolution.EffectiveRole);
        Assert.Equal(RoleCatalog.BimManager, resolution.MatchedRoles[0]);
        Assert.Equal(RoleCatalog.Executor, resolution.MatchedRoles[1]);
    }

    [Fact]
    public void ToString_ReturnsSystemNameOfEffectiveRole()
    {
        RoleResolution resolution = RoleCatalog.ResolveFromRoles([RoleCatalog.Gip]);

        Assert.Equal("GIP", resolution.ToString());
    }

    [Fact]
    public void Constructor_NullArguments_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new RoleResolution(null!, []));
        Assert.Throws<ArgumentNullException>(() => new RoleResolution(RoleCatalog.Guest, null!));
    }

    #endregion
}
