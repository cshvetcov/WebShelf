using WebShelf.Classes.DC;
using WebShelf.Classes.Security;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты каталога ролей RoleCatalog: состав ролей и их старшинство, построение
/// шаблонов и фактических имён AD-групп, обратный поиск по именам, чистая функция
/// вычисления ролей по группам пользователя (Гость при отсутствии ролевых групп,
/// старшая роль при пересечении) и самопроверка каталога.
/// </summary>
public class RoleCatalogTests
{
    /// <summary>
    /// Короткий префикс InstanceId, используемый в тестах (Debug-сборка: 26 нулей).
    /// </summary>
    private const string InstanceIdShort = "000000000000";

    #region Состав каталога и самопроверка

    [Fact]
    public void Validate_CatalogIsConsistent_ReturnsTrue()
    {
        Assert.True(RoleCatalog.Validate());
    }

    [Fact]
    public void AdRoles_ContainsNineRolesInSeniorityOrder()
    {
        Assert.Equal(9, RoleCatalog.AdRoles.Count);

        // Порядок объявления = старшинство: Администратор (0) … Заказчик (8)
        Assert.Equal(AppRoleId.Administrator, RoleCatalog.AdRoles[0].Id);
        Assert.Equal(AppRoleId.Customer, RoleCatalog.AdRoles[8].Id);

        // Список всех ролей включает Гостя
        Assert.Equal(10, RoleCatalog.AllRoles.Count);
        Assert.Contains(RoleCatalog.AllRoles, role => role.Id == AppRoleId.Guest);
    }

    [Fact]
    public void Guest_HasNoGroupSuffixAndLowestSeniority()
    {
        Assert.Null(RoleCatalog.Guest.GroupSuffix);
        Assert.Equal(9, RoleCatalog.Guest.SeniorityIndex);
    }

    [Fact]
    public void SeniorityIndex_MatchesEnumValue()
    {
        foreach (AppRole role in RoleCatalog.AllRoles)
        {
            Assert.Equal((byte)role.Id, role.SeniorityIndex);
        }
    }

    #endregion

    #region Шаблоны и имена групп

    [Fact]
    public void BuildGroupNameTemplates_ReturnsTemplatePerAdRole_WithoutUsersAndGuest()
    {
        string[] templates = RoleCatalog.BuildGroupNameTemplates();

        Assert.Equal(9, templates.Length);

        Assert.All(templates, template =>
            Assert.Contains(AdNames.InstanceIdShortPlaceholder, template));

        // Группа доступа Users и роль Гость в шаблоны ролевых групп не входят
        Assert.DoesNotContain(templates, template => template.EndsWith("-Users", StringComparison.Ordinal));
        Assert.DoesNotContain(templates, template => template.EndsWith("-Guest", StringComparison.Ordinal));

        // Шаблоны формируются в порядке старшинства ролей
        Assert.Equal($"WebShelf-{AdNames.InstanceIdShortPlaceholder}-Administrator", templates[0]);
        Assert.Equal($"WebShelf-{AdNames.InstanceIdShortPlaceholder}-Customer", templates[8]);
    }

    [Fact]
    public void BuildGroupName_CombinesPrefixAndSuffix()
    {
        string groupName = RoleCatalog.BuildGroupName(RoleCatalog.Gip, InstanceIdShort);

        Assert.Equal($"WebShelf-{InstanceIdShort}-GIP", groupName);
    }

    [Fact]
    public void BuildGroupName_ForGuest_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => RoleCatalog.BuildGroupName(RoleCatalog.Guest, InstanceIdShort));
    }

    #endregion

    #region Обратный поиск

    [Fact]
    public void TryGetBySystemName_KnownName_ReturnsRole()
    {
        // Поиск без учёта регистра
        Assert.Equal(AppRoleId.Administrator, RoleCatalog.TryGetBySystemName("Administrator")!.Id);
        Assert.Equal(AppRoleId.Administrator, RoleCatalog.TryGetBySystemName("administrator")!.Id);
        Assert.Equal(AppRoleId.BimManager, RoleCatalog.TryGetBySystemName("BIMManager")!.Id);
        Assert.Equal(AppRoleId.Gip, RoleCatalog.TryGetBySystemName("GIP")!.Id);
        Assert.Equal(AppRoleId.Guest, RoleCatalog.TryGetBySystemName("Guest")!.Id);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Unknown")]
    [InlineData("Администратор")]
    public void TryGetBySystemName_UnknownName_ReturnsNull(string? systemName)
    {
        Assert.Null(RoleCatalog.TryGetBySystemName(systemName));
    }

    [Fact]
    public void TryGetByGroupName_MatchesRoleGroup_CaseInsensitive()
    {
        AppRole? role = RoleCatalog.TryGetByGroupName($"WebShelf-{InstanceIdShort}-GIP", InstanceIdShort);

        Assert.NotNull(role);
        Assert.Equal(AppRoleId.Gip, role!.Id);

        // Имя группы в AD регистронезависимо
        AppRole? caseInsensitive = RoleCatalog.TryGetByGroupName(
            $"webshelf-{InstanceIdShort}-gip", InstanceIdShort);
        Assert.NotNull(caseInsensitive);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Domain Users")]
    [InlineData("WebShelf-Users")]
    [InlineData("WebShelf-111111111111-GIP")]
    [InlineData("WebShelf-000000000000-Guest")]
    public void TryGetByGroupName_NonRoleGroup_ReturnsNull(string? groupName)
    {
        Assert.Null(RoleCatalog.TryGetByGroupName(groupName, InstanceIdShort));
    }

    #endregion

    #region Вычисление роли по группам

    [Fact]
    public void ResolveFromGroupNames_NoGroups_ReturnsGuest()
    {
        RoleResolution resolution = RoleCatalog.ResolveFromGroupNames([], InstanceIdShort);

        Assert.True(resolution.IsGuest);
        Assert.Equal(AppRoleId.Guest, resolution.EffectiveRole.Id);
        Assert.Empty(resolution.MatchedRoles);
    }

    [Fact]
    public void ResolveFromGroupNames_OnlyUsersGroup_ReturnsGuest()
    {
        // Группа доступа Users — не роль: сама по себе роли не даёт
        string[] groups = [$"WebShelf-{InstanceIdShort}-Users"];

        RoleResolution resolution = RoleCatalog.ResolveFromGroupNames(groups, InstanceIdShort);

        Assert.True(resolution.IsGuest);
        Assert.Empty(resolution.MatchedRoles);
    }

    [Fact]
    public void ResolveFromGroupNames_SingleRoleGroup_ReturnsThatRole()
    {
        string[] groups =
        [
            $"WebShelf-{InstanceIdShort}-Users",
            $"WebShelf-{InstanceIdShort}-Executor",
            "Domain Users"
        ];

        RoleResolution resolution = RoleCatalog.ResolveFromGroupNames(groups, InstanceIdShort);

        Assert.False(resolution.IsGuest);
        Assert.Equal(AppRoleId.Executor, resolution.EffectiveRole.Id);
        Assert.Single(resolution.MatchedRoles);
    }

    [Fact]
    public void ResolveFromGroupNames_MultipleRoles_EffectiveIsMostSenior()
    {
        // Исполнитель + Менеджер + ГИП: действует Менеджер (индекс 3 старше ГИП 4 и Исполнителя 6)
        string[] groups =
        [
            $"WebShelf-{InstanceIdShort}-Executor",
            $"WebShelf-{InstanceIdShort}-Manager",
            $"WebShelf-{InstanceIdShort}-GIP"
        ];

        RoleResolution resolution = RoleCatalog.ResolveFromGroupNames(groups, InstanceIdShort);

        Assert.Equal(AppRoleId.Manager, resolution.EffectiveRole.Id);
        Assert.Equal(3, resolution.MatchedRoles.Count);

        // Список назначенных ролей упорядочен по старшинству
        Assert.Equal(AppRoleId.Manager, resolution.MatchedRoles[0].Id);
        Assert.Equal(AppRoleId.Gip, resolution.MatchedRoles[1].Id);
        Assert.Equal(AppRoleId.Executor, resolution.MatchedRoles[2].Id);
    }

    [Fact]
    public void ResolveFromGroupNames_AdministratorBeatsAllRoles()
    {
        string[] groups =
        [
            $"WebShelf-{InstanceIdShort}-Administrator",
            $"WebShelf-{InstanceIdShort}-Director",
            $"WebShelf-{InstanceIdShort}-Customer"
        ];

        RoleResolution resolution = RoleCatalog.ResolveFromGroupNames(groups, InstanceIdShort);

        Assert.Equal(AppRoleId.Administrator, resolution.EffectiveRole.Id);
    }

    [Fact]
    public void ResolveFromGroupNames_DuplicateGroups_MatchedOnce()
    {
        string[] groups =
        [
            $"WebShelf-{InstanceIdShort}-Executor",
            $"webshelf-{InstanceIdShort}-executor"
        ];

        RoleResolution resolution = RoleCatalog.ResolveFromGroupNames(groups, InstanceIdShort);

        Assert.Single(resolution.MatchedRoles);
    }

    [Fact]
    public void ResolveFromGroupNames_GroupNameCaseInsensitive()
    {
        string[] groups = [$"WEBSHELF-{InstanceIdShort.ToUpperInvariant()}-DIRECTOR"];

        RoleResolution resolution = RoleCatalog.ResolveFromGroupNames(groups, InstanceIdShort);

        Assert.Equal(AppRoleId.Director, resolution.EffectiveRole.Id);
    }

    [Fact]
    public void ResolveFromGroupNames_EmptyInstanceId_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => RoleCatalog.ResolveFromGroupNames([], " "));
    }

    #endregion

    #region ResolveFromRoles и MostSenior

    [Fact]
    public void ResolveFromRoles_EmptyList_ReturnsGuest()
    {
        RoleResolution resolution = RoleCatalog.ResolveFromRoles([]);

        Assert.True(resolution.IsGuest);
        Assert.Empty(resolution.MatchedRoles);
    }

    [Fact]
    public void ResolveFromRoles_DuplicatesAndUnorderedInput_SeniorityOrderAndDeduplication()
    {
        List<AppRole> roles =
        [
            RoleCatalog.Executor,
            RoleCatalog.Administrator,
            RoleCatalog.Executor,
            RoleCatalog.GroupLeader
        ];

        RoleResolution resolution = RoleCatalog.ResolveFromRoles(roles);

        Assert.Equal(3, resolution.MatchedRoles.Count);
        Assert.Equal(AppRoleId.Administrator, resolution.EffectiveRole.Id);
        Assert.Equal(AppRoleId.GroupLeader, resolution.MatchedRoles[1].Id);
        Assert.Equal(AppRoleId.Executor, resolution.MatchedRoles[2].Id);
    }

    [Fact]
    public void MostSenior_ReturnsLowestSeniorityIndex()
    {
        AppRole? mostSenior = RoleCatalog.MostSenior([RoleCatalog.Customer, RoleCatalog.Director, RoleCatalog.Gip]);

        Assert.NotNull(mostSenior);
        Assert.Equal(AppRoleId.Director, mostSenior!.Id);
    }

    [Fact]
    public void MostSenior_EmptySet_ReturnsNull()
    {
        Assert.Null(RoleCatalog.MostSenior([]));
    }

    #endregion
}
