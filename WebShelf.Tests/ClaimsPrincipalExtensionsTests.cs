using System.Security.Claims;
using WebShelf.Classes.Security;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты расширений ClaimsPrincipal: чтение действующей роли из утверждений
/// (в том числе по cookie, выданной до введения ролей), проверка принадлежности
/// к роли и пороговая проверка «не ниже указанной».
/// </summary>
public class ClaimsPrincipalExtensionsTests
{
    #region Вспомогательные методы

    /// <summary>
    /// Строит пользователя с указанными утверждениями (имя + роль + назначенные роли).
    /// </summary>
    private static ClaimsPrincipal BuildUser(string? roleSystemName, string? matchedRoles = null, bool authenticated = true)
    {
        List<Claim> claims = [new Claim(ClaimTypes.Name, "ivanov")];

        if (roleSystemName is not null)
        {
            claims.Add(new Claim(ClaimTypes.Role, roleSystemName));
        }

        if (matchedRoles is not null)
        {
            claims.Add(new Claim(ClaimsPrincipalExtensions.MatchedRolesClaimType, matchedRoles));
        }

        ClaimsIdentity identity = new(claims, authenticated ? "WebShelf.Auth" : null);
        return new ClaimsPrincipal(identity);
    }

    #endregion

    #region GetAppRole

    [Fact]
    public void GetAppRole_RoleClaim_ReturnsCatalogRole()
    {
        Assert.Equal(AppRoleId.Administrator, BuildUser("Administrator").GetAppRole()!.Id);
        Assert.Equal(AppRoleId.Gip, BuildUser("GIP").GetAppRole()!.Id);
        Assert.Equal(AppRoleId.Guest, BuildUser("Guest").GetAppRole()!.Id);
    }

    [Fact]
    public void GetAppRole_NoRoleClaim_ReturnsNull()
    {
        // Cookie, выданная до введения ролей, не содержит утверждения роли
        ClaimsPrincipal user = BuildUser(roleSystemName: null);

        Assert.Null(user.GetAppRole());
    }

    [Fact]
    public void GetAppRole_UnknownRoleName_ReturnsNull()
    {
        ClaimsPrincipal user = BuildUser("SuperUser");

        Assert.Null(user.GetAppRole());
    }

    [Fact]
    public void GetAppRole_AnonymousUser_ReturnsNull()
    {
        ClaimsPrincipal anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        Assert.Null(anonymous.GetAppRole());
    }

    [Fact]
    public void GetAppRole_NullPrincipal_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => ((ClaimsPrincipal)null!).GetAppRole());
    }

    #endregion

    #region IsInRole и IsAtLeast

    [Fact]
    public void IsInRole_MatchingRole_ReturnsTrue()
    {
        ClaimsPrincipal user = BuildUser("Manager");

        Assert.True(user.IsInRole(AppRoleId.Manager));
        Assert.False(user.IsInRole(AppRoleId.Administrator));
    }

    [Theory]
    [InlineData("Administrator", "Manager", true)]   // Администратор выше Менеджера
    [InlineData("Manager", "Manager", true)]         // равная роль
    [InlineData("Director", "Manager", true)]        // Директор выше Менеджера
    [InlineData("GIP", "Manager", false)]            // ГИП ниже Менеджера
    [InlineData("Guest", "Guest", true)]             // равная роль (Гость)
    [InlineData("Guest", "Customer", false)]         // Гость ниже Заказчика
    [InlineData("Customer", "Guest", true)]          // Заказчик выше Гостя
    public void IsAtLeast_SeniorityComparison(string userRole, string minimumRole, bool expected)
    {
        ClaimsPrincipal user = BuildUser(userRole);
        AppRoleId minimum = Enum.Parse<AppRoleId>(minimumRole);

        Assert.Equal(expected, user.IsAtLeast(minimum));
    }

    [Fact]
    public void IsAtLeast_NoRoleClaim_ReturnsFalse()
    {
        ClaimsPrincipal user = BuildUser(roleSystemName: null);

        Assert.False(user.IsAtLeast(AppRoleId.Guest));
    }

    #endregion
}
