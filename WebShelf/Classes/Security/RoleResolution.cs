namespace WebShelf.Classes.Security;

/// <summary>
/// Результат вычисления ролей пользователя: эффективная роль (действующая
/// при пересечении нескольких), полный список назначенных ролей и членство
/// в группе доступа Users. Экземпляры создаёт только <see cref="RoleCatalog"/>;
/// список <see cref="MatchedRoles"/> упорядочен по старшинству (старшая роль первой).
/// Резолвер <see cref="RoleResolver"/> использует тот же тип: дополнительно
/// заполняет <see cref="HasUsersGroup"/> по прямым группам пользователя.
/// </summary>
internal sealed class RoleResolution : IEquatable<RoleResolution>
{
    /// <summary>
    /// Создаёт результат вычисления ролей. Вызывается только из <see cref="RoleCatalog"/>
    /// и <see cref="RoleResolver"/>.
    /// </summary>
    /// <param name="effectiveRole">Действующая роль (старшая из назначенных либо Гость).</param>
    /// <param name="matchedRoles">Назначенные роли, упорядоченные по старшинству; пусто для Гостя.</param>
    /// <param name="hasUsersGroup">Членство в группе доступа WebShelf-{InstanceIdShort}-Users.</param>
    internal RoleResolution(AppRole effectiveRole, IReadOnlyList<AppRole> matchedRoles, bool hasUsersGroup = false)
    {
        EffectiveRole = effectiveRole ?? throw new ArgumentNullException(nameof(effectiveRole));
        MatchedRoles = matchedRoles ?? throw new ArgumentNullException(nameof(matchedRoles));
        HasUsersGroup = hasUsersGroup;
    }

    /// <summary>
    /// Действующая роль: старшая из назначенных; Гость, если ролевых групп нет.
    /// </summary>
    internal AppRole EffectiveRole { get; }

    /// <summary>
    /// Все назначенные роли, упорядоченные по старшинству (старшая первой).
    /// Пустой список — пользователь состоит только в группе доступа Users либо ни в одной ролевой группе.
    /// </summary>
    internal IReadOnlyList<AppRole> MatchedRoles { get; }

    /// <summary>
    /// Членство в группе доступа <c>WebShelf-{InstanceIdShort}-Users</c>.
    /// Заполняется резолвером <see cref="RoleResolver"/> по прямым группам
    /// пользователя; при вычислении через <see cref="RoleCatalog"/> считается
    /// неопределённым (<see langword="false"/>). Потеря группы — принудительный
    /// выход: провайдер цепочки переводит пользователя в анонимное состояние.
    /// </summary>
    internal bool HasUsersGroup { get; }

    /// <summary>
    /// <see langword="true"/>, если действующая роль — Гость (ролевые группы отсутствуют).
    /// </summary>
    internal bool IsGuest => EffectiveRole.Id == AppRoleId.Guest;

    /// <summary>
    /// Результаты равны, если совпадают действующая роль и набор назначенных ролей.
    /// </summary>
    public bool Equals(RoleResolution? other) =>
        other is not null
        && EffectiveRole.Id == other.EffectiveRole.Id
        && MatchedRoles.Count == other.MatchedRoles.Count
        && MatchedRoles.Zip(other.MatchedRoles, (first, second) => first.Id == second.Id).All(equal => equal);

    /// <summary>
    /// Сравнение с любым объектом через <see cref="Equals(RoleResolution)"/>.
    /// </summary>
    public override bool Equals(object? obj) => Equals(obj as RoleResolution);

    /// <summary>
    /// Хеш-код по идентификаторам ролей.
    /// </summary>
    public override int GetHashCode()
    {
        HashCode hash = new HashCode();
        hash.Add(EffectiveRole.Id);
        foreach (AppRole role in MatchedRoles)
        {
            hash.Add(role.Id);
        }

        return hash.ToHashCode();
    }

    /// <summary>
    /// Строковое представление — системное имя действующей роли.
    /// </summary>
    public override string ToString() => EffectiveRole.SystemName;
}
