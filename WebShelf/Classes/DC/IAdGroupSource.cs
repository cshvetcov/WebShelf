namespace WebShelf.Classes.DC;

/// <summary>
/// Источник данных о группах AD для ролевой модели WebShelf.
/// Изолирует резолвер ролей (<c>WebShelf.Classes.Security</c>) от конкретной
/// реализации доступа к домену и позволяет тестировать его на подменах.
/// Единственная реализация — <see cref="Domain"/>.
/// </summary>
internal interface IAdGroupSource
{
    /// <summary>
    /// Возвращает расширенное имя группы WebShelf по суффиксу:
    /// например, "GIP" → WebShelf-000000000000-GIP (Debug-сборка).
    /// </summary>
    /// <param name="suffix">Суффикс группы: "Users" либо суффикс ролевой группы.</param>
    /// <returns>Имя группы с подставленным InstanceIdShort. <see langword="null"/> при ошибке.</returns>
    string? GetExpandedGroupName(string suffix);

    /// <summary>
    /// Возвращает прямые группы, в которых состоит пользователь
    /// (вложенные группы не учитываются — аналогично проверке Users при входе).
    /// Для каждой группы берётся sAMAccountName, при его отсутствии — Name.
    /// </summary>
    /// <param name="samAccountName">Имя учётной записи (sAMAccountName, без доменной части).</param>
    /// <returns>
    /// Список имён групп. Пустой список — пользователь найден, но не состоит ни в одной
    /// группе (в том числе пользователь удалён из AD); <see langword="null"/> — ошибка
    /// обращения к AD (резолвер в этом случае не меняет известное состояние).
    /// </returns>
    IReadOnlyList<string>? GetUserGroupNames(string samAccountName);
}
