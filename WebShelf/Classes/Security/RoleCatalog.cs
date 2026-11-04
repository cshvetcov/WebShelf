using WebShelf.Classes.DC;

namespace WebShelf.Classes.Security;

/// <summary>
/// Каталог ролей WebShelf — единый источник истины о составе ролей, их именах,
/// соответствии AD-группам и старшинстве. Все шаблоны имён ролевых групп
/// (<see cref="Domain.FillRequiredGroupsFromTemplates"/>) выгружаются из этого
/// каталога, поэтому добавление новой роли автоматически даёт: создание группы
/// при старте, участие в вычислении роли и отображение в интерфейсе.
/// Класс статичен; экземпляры <see cref="AppRole"/> создаются только здесь.
/// </summary>
internal static class RoleCatalog
{
    /// <summary>
    /// Роль «Администратор».
    /// </summary>
    internal static AppRole Administrator { get; } = new(AppRoleId.Administrator, "Administrator", "Администратор", "Administrator");

    /// <summary>
    /// Роль «Директор».
    /// </summary>
    internal static AppRole Director { get; } = new(AppRoleId.Director, "Director", "Директор", "Director");

    /// <summary>
    /// Роль «BIM-менеджер».
    /// </summary>
    internal static AppRole BimManager { get; } = new(AppRoleId.BimManager, "BIMManager", "BIM-менеджер", "BIMManager");

    /// <summary>
    /// Роль «Менеджер».
    /// </summary>
    internal static AppRole Manager { get; } = new(AppRoleId.Manager, "Manager", "Менеджер", "Manager");

    /// <summary>
    /// Роль «ГИП».
    /// </summary>
    internal static AppRole Gip { get; } = new(AppRoleId.Gip, "GIP", "ГИП", "GIP");

    /// <summary>
    /// Роль «Руководитель группы».
    /// </summary>
    internal static AppRole GroupLeader { get; } = new(AppRoleId.GroupLeader, "GroupLeader", "Руководитель группы", "GroupLeader");

    /// <summary>
    /// Роль «Исполнитель».
    /// </summary>
    internal static AppRole Executor { get; } = new(AppRoleId.Executor, "Executor", "Исполнитель", "Executor");

    /// <summary>
    /// Роль «Внешний исполнитель».
    /// </summary>
    internal static AppRole ExternalExecutor { get; } = new(AppRoleId.ExternalExecutor, "ExternalExecutor", "Внешний исполнитель", "ExternalExecutor");

    /// <summary>
    /// Роль «Заказчик».
    /// </summary>
    internal static AppRole Customer { get; } = new(AppRoleId.Customer, "Customer", "Заказчик", "Customer");

    /// <summary>
    /// Роль «Гость» — единственная роль без AD-группы: применяется автоматически,
    /// если пользователь не состоит ни в одной ролевой группе.
    /// </summary>
    internal static AppRole Guest { get; } = new(AppRoleId.Guest, "Guest", "Гость", null);

    /// <summary>
    /// Роли, назначаемые через AD-группы, упорядоченные по старшинству (старшая первая).
    /// Роль Гость в список не входит.
    /// </summary>
    internal static readonly IReadOnlyList<AppRole> AdRoles =
    [
        Administrator,
        Director,
        BimManager,
        Manager,
        Gip,
        GroupLeader,
        Executor,
        ExternalExecutor,
        Customer
    ];

    /// <summary>
    /// Все роли, включая Гостя, упорядоченные по старшинству (старшая первая).
    /// </summary>
    internal static readonly IReadOnlyList<AppRole> AllRoles =
    [
        .. AdRoles,
        Guest
    ];

    /// <summary>
    /// Строит шаблоны имён ролевых AD-групп для <see cref="Domain.FillRequiredGroupsFromTemplates"/>:
    /// по одному шаблону на каждую роль каталога. Группа доступа Users и роль Гость
    /// сюда не входят: Users — не роль (шаблон хранится в <see cref="Domain"/>),
    /// Гость не назначается через AD.
    /// </summary>
    /// <returns>Массив шаблонов вида <c>WebShelf-{InstanceIdShort}-Administrator</c>.</returns>
    internal static string[] BuildGroupNameTemplates() =>
        AdRoles.Select(role => $"WebShelf-{Domain.InstanceIdShortPlaceholder}-{role.GroupSuffix}").ToArray();

    /// <summary>
    /// Строит фактическое имя AD-группы указанной роли для заданного экземпляра.
    /// </summary>
    /// <param name="role">Роль; должна иметь суффикс группы (не Гость).</param>
    /// <param name="instanceIdShort">Короткий префикс InstanceId (12 символов, нижний регистр).</param>
    /// <returns>Имя группы вида <c>WebShelf-000000000000-Administrator</c>.</returns>
    /// <exception cref="ArgumentException">Если роль не имеет AD-группы (Гость) или префикс пуст.</exception>
    internal static string BuildGroupName(AppRole role, string instanceIdShort)
    {
        if (role.GroupSuffix is null)
            throw new ArgumentException($"Роль {role.SystemName} не имеет AD-группы.", nameof(role));
        if (string.IsNullOrWhiteSpace(instanceIdShort))
            throw new ArgumentException("Короткий префикс InstanceId не может быть пустым.", nameof(instanceIdShort));

        return $"WebShelf-{instanceIdShort}-{role.GroupSuffix}";
    }

    /// <summary>
    /// Вычисляет роли пользователя по именам групп, в которых он состоит напрямую.
    /// Группа доступа Users и посторонние группы игнорируются; если ни одна ролевая
    /// группа не найдена, действует роль Гость.
    /// </summary>
    /// <param name="groupNames">Имена групп пользователя (sAMAccountName или Name из AD).</param>
    /// <param name="instanceIdShort">Короткий префикс InstanceId текущего экземпляра.</param>
    /// <returns>
    /// Результат с действующей ролью (старшей из назначенных) и полным списком назначенных ролей.
    /// </returns>
    /// <remarks>
    /// Сравнение имён групп выполняется без учёта регистра (OrdinalIgnoreCase) —
    /// как и поиск групп в AD. Метод чистый: не обращается к AD и полностью покрывается юнит-тестами.
    /// </remarks>
    internal static RoleResolution ResolveFromGroupNames(IEnumerable<string> groupNames, string instanceIdShort)
    {
        ArgumentNullException.ThrowIfNull(groupNames);
        if (string.IsNullOrWhiteSpace(instanceIdShort))
            throw new ArgumentException("Короткий префикс InstanceId не может быть пустым.", nameof(instanceIdShort));

        List<AppRole> matchedRoles = [];

        foreach (string groupName in groupNames)
        {
            AppRole? role = TryGetByGroupName(groupName, instanceIdShort);
            if (role is not null && !matchedRoles.Contains(role))
            {
                matchedRoles.Add(role);
            }
        }

        return ResolveFromRoles(matchedRoles);
    }

    /// <summary>
    /// Формирует результат вычисления ролей по списку назначенных ролей:
    /// дубликаты отбрасываются, список упорядочивается по старшинству,
    /// действующей становится старшая роль; пустой список даёт Гостя.
    /// </summary>
    /// <param name="roles">Назначенные роли (в любом порядке, возможны дубликаты).</param>
    /// <returns>Результат вычисления ролей.</returns>
    internal static RoleResolution ResolveFromRoles(IEnumerable<AppRole> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);

        List<AppRole> matchedRoles = roles
            .Distinct()
            .OrderBy(role => role.SeniorityIndex)
            .ToList();

        AppRole effectiveRole = matchedRoles.Count > 0 ? matchedRoles[0] : Guest;

        return new RoleResolution(effectiveRole, matchedRoles);
    }

    /// <summary>
    /// Возвращает старшую роль из набора (с наименьшим индексом старшинства).
    /// </summary>
    /// <param name="roles">Набор ролей.</param>
    /// <returns>Старшая роль; <see langword="null"/>, если набор пуст.</returns>
    internal static AppRole? MostSenior(IEnumerable<AppRole> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);

        AppRole? mostSenior = null;
        foreach (AppRole role in roles)
        {
            if (mostSenior is null || role.SeniorityIndex < mostSenior.SeniorityIndex)
            {
                mostSenior = role;
            }
        }

        return mostSenior;
    }

    /// <summary>
    /// Ищет роль по системному имени (содержимое claim роли).
    /// </summary>
    /// <param name="systemName">Системное имя роли, например <c>Administrator</c>.</param>
    /// <returns>Роль каталога; <see langword="null"/>, если имя не найдено.</returns>
    internal static AppRole? TryGetBySystemName(string? systemName)
    {
        if (string.IsNullOrWhiteSpace(systemName))
        {
            return null;
        }

        foreach (AppRole role in AllRoles)
        {
            if (string.Equals(role.SystemName, systemName, StringComparison.OrdinalIgnoreCase))
            {
                return role;
            }
        }

        return null;
    }

    /// <summary>
    /// Ищет роль по полному имени AD-группы текущего экземпляра
    /// (<c>WebShelf-{InstanceIdShort}-{суффикс}</c>), без учёта регистра.
    /// </summary>
    /// <param name="groupName">Имя группы из AD (sAMAccountName или Name).</param>
    /// <param name="instanceIdShort">Короткий префикс InstanceId текущего экземпляра.</param>
    /// <returns>Роль каталога; <see langword="null"/>, если группа не является ролевой.</returns>
    internal static AppRole? TryGetByGroupName(string? groupName, string instanceIdShort)
    {
        if (string.IsNullOrWhiteSpace(groupName))
        {
            return null;
        }

        foreach (AppRole role in AdRoles)
        {
            if (string.Equals(groupName, BuildGroupName(role, instanceIdShort), StringComparison.OrdinalIgnoreCase))
            {
                return role;
            }
        }

        return null;
    }

    /// <summary>
    /// Самопроверка каталога: уникальность идентификаторов, системных имён
    /// и суффиксов групп; непустые имена; у Гостя нет суффикса.
    /// Вызывается при старте приложения и в юнит-тестах.
    /// </summary>
    /// <returns>
    /// <see langword="true"/>, если каталог консистентен;
    /// <see langword="false"/>, если найдены дубликаты или пустые значения.
    /// </returns>
    internal static bool Validate()
    {
        List<AppRole> all = [.. AllRoles];

        if (all.Count != Enum.GetValues<AppRoleId>().Length)
        {
            return false;
        }

        if (all.Select(role => role.Id).Distinct().Count() != all.Count
            || all.Select(role => role.SystemName).Distinct(StringComparer.OrdinalIgnoreCase).Count() != all.Count
            || all.Select(role => role.DisplayName).Distinct(StringComparer.OrdinalIgnoreCase).Count() != all.Count)
        {
            return false;
        }

        List<AppRole> adRoles = [.. AdRoles];
        if (adRoles.Select(role => role.GroupSuffix).Distinct(StringComparer.OrdinalIgnoreCase).Count() != adRoles.Count)
        {
            return false;
        }

        foreach (AppRole role in adRoles)
        {
            if (string.IsNullOrWhiteSpace(role.GroupSuffix))
            {
                return false;
            }
        }

        return Guest.GroupSuffix is null;
    }
}
