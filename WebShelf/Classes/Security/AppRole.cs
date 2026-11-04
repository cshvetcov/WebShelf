namespace WebShelf.Classes.Security;

/// <summary>
/// Роль приложения WebShelf. Экземпляры создаёт только <see cref="AppRoleCatalog"/>:
/// состав ролей фиксирован, старшинство задаётся индексом (меньше — старше).
/// Роль не хранит состояние: эффективная роль пользователя всегда вычисляется
/// по его прямым группам AD.
/// </summary>
internal sealed class AppRole
{
    /// <summary>
    /// Числовой идентификатор роли. Совпадает с индексом старшинства; справочная величина.
    /// </summary>
    internal int Id { get; }

    /// <summary>
    /// Системное имя (латиница, стабильно между версиями). Кладётся в клейм
    /// <c>ClaimTypes.Role</c> и используется в <c>[Authorize(Roles = ...)]</c>.
    /// </summary>
    internal string SystemName { get; }

    /// <summary>
    /// Отображаемое имя (кириллица) для UI — в частности, для ленты:
    /// <c>ivanov [Администратор] Выйти</c>.
    /// </summary>
    internal string DisplayName { get; }

    /// <summary>
    /// Суффикс AD-группы роли: <c>WebShelf-{InstanceIdShort}-{GroupSuffix}</c>.
    /// <see langword="null"/> у Гостя — под Гостя группа в AD не создаётся.
    /// </summary>
    internal string? GroupSuffix { get; }

    /// <summary>
    /// Индекс старшинства: 0 — старшая роль. При членстве в нескольких ролевых
    /// группах действует роль с наименьшим индексом.
    /// </summary>
    internal int SeniorityIndex { get; }

    private AppRole(int id, string systemName, string displayName, string? groupSuffix, int seniorityIndex)
    {
        Id = id;
        SystemName = systemName;
        DisplayName = displayName;
        GroupSuffix = groupSuffix;
        SeniorityIndex = seniorityIndex;
    }
}
