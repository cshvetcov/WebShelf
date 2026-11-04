namespace WebShelf.Classes.Security;

/// <summary>
/// Событие для активных цепочек пользователя: смена роли либо принудительный выход.
/// </summary>
/// <param name="Username">sAMAccountName пользователя (в логах маскируется).</param>
/// <param name="Resolution">Новое состояние ролей; <see langword="null"/> — принудительный выход (потеря группы Users).</param>
/// <param name="Reason">Причина: <see cref="ReasonRoleChanged"/> либо <see cref="ReasonUsersGroupLost"/>.</param>
internal sealed record RoleChange(string Username, RoleResolution? Resolution, string Reason)
{
    internal const string ReasonRoleChanged = "role-changed";

    internal const string ReasonUsersGroupLost = "users-group-lost";
}

/// <summary>
/// Рассылает события смены роли подписчикам. Источник событий — singleton
/// <see cref="RoleRefreshService"/>; единственный подписчик — scoped
/// <see cref="AppAuthenticationStateProvider"/> каждой активной цепочки.
/// Связь «singleton → scoped» напрямую через DI невозможна, поэтому идёт через событие.
/// </summary>
internal sealed class RoleChangeNotifier
{
    private const string ClassName = "WebShelf.Classes.Security.RoleChangeNotifier";

    /// <summary>
    /// Событие вызывается из фонового потока службы опроса: подписчики обязаны
    /// обеспечивать потокобезопасность (провайдер подменяет состояние атомарной
    /// заменой задачи и уведомляет Blazor через NotifyAuthenticationStateChanged).
    /// </summary>
    internal event EventHandler<RoleChange>? RoleChanged;

    /// <summary>
    /// Конструктор объявлен <see langword="public"/> (сам класс остаётся internal):
    /// контейнер DI находит только public-конструкторы.
    /// </summary>
    public RoleChangeNotifier()
    {
    }

    /// <summary>
    /// Вызывает событие и пишет его в лог (аудит смены роли).
    /// </summary>
    /// <param name="change">Событие для рассылки.</param>
    internal void Raise(RoleChange change)
    {
        const string method = nameof(Raise);

        try
        {
            Log.Information(
                "Событие смены роли. Username={User}, Reason={Reason}, NewRole={NewRole}, MatchedRoles={Matched}. Class={Class}, Method={Method}",
                "UserAccount",
                change.Reason,
                change.Resolution?.Role.SystemName ?? "—",
                change.Resolution is null
                    ? "—"
                    : string.Join(",", change.Resolution.MatchedRoles.Select(role => role.SystemName)),
                ClassName, method);

            EventHandler<RoleChange>? handlers = RoleChanged;
            handlers?.Invoke(this, change);
        }
        catch (Exception ex)
        {
            // Ошибка одного подписчика не должна ронять службу опроса
            Log.Error(ex, "Исключение при рассылке события смены роли. Class={Class}, Method={Method}", ClassName, method);
        }
    }
}
