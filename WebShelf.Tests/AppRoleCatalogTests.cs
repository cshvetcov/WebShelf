using WebShelf.Classes.DC;
using WebShelf.Classes.Security;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты каталога ролей AppRoleCatalog: состав и порядок старшинства,
/// поиск по системному имени, шаблоны имён групп для Domain.
/// </summary>
public class AppRoleCatalogTests
{
    /// <summary>
    /// Все роли упорядочены по возрастанию индекса старшинства; Гость — последняя.
    /// </summary>
    [Fact]
    public void All_OrderedBySeniority_GuestLast()
    {
        Assert.Equal(10, AppRoleCatalog.All.Count);

        for (int i = 1; i < AppRoleCatalog.All.Count; i++)
        {
            Assert.True(
                AppRoleCatalog.All[i - 1].SeniorityIndex < AppRoleCatalog.All[i].SeniorityIndex,
                $"Нарушен порядок старшинства на позиции {i}");
        }

        Assert.Same(AppRoleCatalog.Guest, AppRoleCatalog.All[^1]);
    }

    /// <summary>
    /// Системные имена ролей уникальны; у Гостя нет группы, у остальных — есть.
    /// </summary>
    [Fact]
    public void Roles_UniqueSystemNames_GuestHasNoGroup()
    {
        Assert.Equal(
            AppRoleCatalog.All.Count,
            AppRoleCatalog.All.Select(role => role.SystemName).Distinct(StringComparer.OrdinalIgnoreCase).Count());

        Assert.Null(AppRoleCatalog.Guest.GroupSuffix);

        foreach (AppRole role in AppRoleCatalog.All)
        {
            if (!ReferenceEquals(role, AppRoleCatalog.Guest))
            {
                Assert.NotNull(role.GroupSuffix);
            }
        }
    }

    /// <summary>
    /// FindBySystemName находит роль без учёта регистра; пустое и неизвестное имя — null.
    /// </summary>
    [Theory]
    [InlineData("Administrator", "Administrator")]
    [InlineData("administrator", "Administrator")]
    [InlineData("BIMManager", "BIMManager")]
    [InlineData("bimmanager", "BIMManager")]
    [InlineData("Guest", "Guest")]
    [InlineData("", null)]
    [InlineData(null, null)]
    [InlineData("   ", null)]
    [InlineData("Nonexistent", null)]
    public void FindBySystemName_CaseInsensitive_MissingReturnsNull(string? systemName, string? expected)
    {
        AppRole? found = AppRoleCatalog.FindBySystemName(systemName);

        Assert.Equal(expected, found?.SystemName);
    }

    /// <summary>
    /// Шаблоны имён групп: Users + группы всех ролей с суффиксом (без Гостя),
    /// каждый содержит заполнитель InstanceIdShort.
    /// </summary>
    [Fact]
    public void GetGroupNameTemplates_UsersPlusAllRolesExceptGuest()
    {
        IReadOnlyList<string> templates = AppRoleCatalog.GetGroupNameTemplates();

        // Users + 9 ролей с группой (Гость исключён)
        Assert.Equal(10, templates.Count);
        Assert.Contains(templates, t => t.Contains("-Users", StringComparison.Ordinal));
        Assert.DoesNotContain(templates, t => t.Contains("Guest", StringComparison.Ordinal));

        foreach (string template in templates)
        {
            Assert.Contains(Domain.InstanceIdShortPlaceholder, template);
        }
    }
}
