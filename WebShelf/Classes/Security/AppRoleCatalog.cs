using WebShelf.Classes.DC;

namespace WebShelf.Classes.Security;

/// <summary>
/// Каталог ролей WebShelf — единственный источник истины о составе ролей,
/// их старшинстве и соответствии AD-группам. Шаблоны имён групп для
/// <see cref="Domain.FillRequiredGroupsFromTemplates"/> строятся отсюда же,
/// поэтому состав групп в AD всегда соответствует каталогу ролей.
/// </summary>
internal static class AppRoleCatalog
{
    /// <summary>
    /// Тип транспортного клейма со списком всех совпавших ролей через запятую
    /// (для диагностики; эффективная роль хранится в <c>ClaimTypes.Role</c>).
    /// </summary>
    internal const string MatchedRolesClaimType = "ws:matched-roles";

    /// <summary>
    /// Суффикс группы доступа (не роль): членство в WebShelf-{InstanceIdShort}-Users
    /// обязательно для входа в систему.
    /// </summary>
    internal const string UsersGroupSuffix = "Users";

    /// <summary>0) Администратор — максимальный уровень доступа.</summary>
    internal static readonly AppRole Administrator = new(0, "Administrator", "Администратор", "Administrator", 0);

    /// <summary>1) Директор.</summary>
    internal static readonly AppRole Director = new(1, "Director", "Директор", "Director", 1);

    /// <summary>2) BIM-менеджер.</summary>
    internal static readonly AppRole BIMManager = new(2, "BIMManager", "BIM-менеджер", "BIMManager", 2);

    /// <summary>3) Менеджер.</summary>
    internal static readonly AppRole Manager = new(3, "Manager", "Менеджер", "Manager", 3);

    /// <summary>4) ГИП.</summary>
    internal static readonly AppRole GIP = new(4, "GIP", "ГИП", "GIP", 4);

    /// <summary>5) Руководитель группы.</summary>
    internal static readonly AppRole GroupLeader = new(5, "GroupLeader", "Руководитель группы", "GroupLeader", 5);

    /// <summary>6) Исполнитель.</summary>
    internal static readonly AppRole Executor = new(6, "Executor", "Исполнитель", "Executor", 6);

    /// <summary>7) Внешний исполнитель.</summary>
    internal static readonly AppRole ExternalExecutor = new(7, "ExternalExecutor", "Внешний исполнитель", "ExternalExecutor", 7);

    /// <summary>8) Заказчик.</summary>
    internal static readonly AppRole Customer = new(8, "Customer", "Заказчик", "Customer", 8);

    /// <summary>
    /// 9) Гость — пользователь без единой ролевой группы. Под Гостя группа в AD
    /// не создаётся: роль вычисляется как fallback при отсутствии совпадений.
    /// </summary>
    internal static readonly AppRole Guest = new(9, "Guest", "Гость", null, 9);

    /// <summary>
    /// Все роли по возрастанию старшинства (Гость — последняя).
    /// </summary>
    internal static readonly IReadOnlyList<AppRole> All =
    [
        Administrator,
        Director,
        BIMManager,
        Manager,
        GIP,
        GroupLeader,
        Executor,
        ExternalExecutor,
        Customer,
        Guest
    ];

    /// <summary>
    /// Поиск роли по системному имени (без учёта регистра) — например,
    /// по значению клейма <c>ClaimTypes.Role</c>.
    /// </summary>
    /// <param name="systemName">Системное имя роли.</param>
    /// <returns>Найденная роль; <see langword="null"/> — имя не задано или не найдено.</returns>
    internal static AppRole? FindBySystemName(string? systemName)
    {
        if (string.IsNullOrWhiteSpace(systemName))
        {
            return null;
        }

        AppRole? found = All.FirstOrDefault(role =>
            string.Equals(role.SystemName, systemName.Trim(), StringComparison.OrdinalIgnoreCase));

        return found;
    }

    /// <summary>
    /// Шаблоны имён групп безопасности для <see cref="Domain.FillRequiredGroupsFromTemplates"/>:
    /// группа доступа Users и по одной группе на каждую роль с суффиксом.
    /// Гость исключён — под него группа не создаётся. Заполнитель {InstanceIdShort}
    /// заменяется при формировании списка групп.
    /// </summary>
    internal static IReadOnlyList<string> GetGroupNameTemplates()
    {
        List<string> templates =
        [
            $"WebShelf-{Domain.InstanceIdShortPlaceholder}-{UsersGroupSuffix}"
        ];

        templates.AddRange(
            All.Where(role => role.GroupSuffix is not null)
                .Select(role => $"WebShelf-{Domain.InstanceIdShortPlaceholder}-{role.GroupSuffix}"));

        return templates;
    }
}
