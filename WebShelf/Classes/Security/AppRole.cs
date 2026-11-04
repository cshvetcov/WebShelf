namespace WebShelf.Classes.Security;

/// <summary>
/// Роль приложения WebShelf. Экземпляры создаёт только <see cref="RoleCatalog"/>:
/// состав ролей фиксирован, старшинство задаётся идентификатором роли
/// (<see cref="AppRoleId"/>, меньше — старше). Роль не хранит состояние:
/// эффективная роль пользователя всегда вычисляется по его прямым группам AD.
/// </summary>
internal sealed class AppRole
{
    /// <summary>
    /// Идентификатор роли. Совпадает с индексом старшинства; справочная величина.
    /// </summary>
    internal AppRoleId Id { get; }

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
    /// группах действует роль с наименьшим индексом. Всегда равен числовому
    /// значению идентификатора <see cref="Id"/>.
    /// </summary>
    internal int SeniorityIndex { get; }

    /// <summary>
    /// Создаёт роль каталога. Вызывается только из <see cref="RoleCatalog"/>;
    /// для остальных сценариев (в том числе тестов) роли берутся из каталога.
    /// </summary>
    /// <param name="id">Идентификатор роли; совпадает с индексом старшинства.</param>
    /// <param name="systemName">Системное имя (латиница).</param>
    /// <param name="displayName">Отображаемое имя (кириллица).</param>
    /// <param name="groupSuffix">Суффикс AD-группы; <see langword="null"/> у Гостя.</param>
    internal AppRole(AppRoleId id, string systemName, string displayName, string? groupSuffix)
    {
        ArgumentNullException.ThrowIfNull(systemName);
        ArgumentNullException.ThrowIfNull(displayName);

        Id = id;
        SystemName = systemName;
        DisplayName = displayName;
        GroupSuffix = groupSuffix;
        SeniorityIndex = (int)id;
    }
}
