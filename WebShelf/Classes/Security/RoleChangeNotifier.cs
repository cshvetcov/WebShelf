namespace WebShelf.Classes.Security;

/// <summary>
/// Рассылает события смены роли подписчикам конкретного пользователя.
/// Источник событий — singleton <see cref="RoleRefreshService"/>; подписчики —
/// scoped-провайдеры <see cref="AppAuthenticationStateProvider"/> активных цепочек.
/// Связь «singleton → scoped» напрямую через DI невозможна, поэтому идёт через
/// подписки: провайдер цепочки подписывается на события своего пользователя
/// (<see cref="Subscribe"/>) и отписывается при закрытии цепочки.
/// Имя учётной записи сравнивается без учёта регистра (как sAMAccountName в AD).
/// </summary>
internal sealed class RoleChangeNotifier
{
    private const string ClassName = "WebShelf.Classes.Security.RoleChangeNotifier";

    /// <summary>Подписки по имени учётной записи (без учёта регистра).</summary>
    private readonly Dictionary<string, List<Action<RoleResolution>>> _subscriptions =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Сериализация изменений списка подписок: опрос и цепочки работают в разных потоках.</summary>
    private readonly object _lock = new();

    /// <summary>
    /// Конструктор объявлен <see langword="public"/> (сам класс остаётся internal):
    /// контейнер DI находит только public-конструкторы.
    /// </summary>
    public RoleChangeNotifier()
    {
    }

    /// <summary>
    /// Подписывает обработчик на события смены роли пользователя. Обработчик
    /// вызывается из фонового потока службы опроса: подписчик обязан обеспечивать
    /// потокобезопасность (провайдер подменяет состояние атомарной заменой задачи
    /// и уведомляет Blazor через NotifyAuthenticationStateChanged).
    /// </summary>
    /// <param name="username">Имя учётной записи (sAMAccountName), события которого нужны подписчику.</param>
    /// <param name="handler">Обработчик события; получает новое состояние ролей пользователя.</param>
    /// <returns>Подписка: освобождение (<see cref="IDisposable.Dispose"/>) отписывает обработчик.</returns>
    /// <exception cref="ArgumentException">Если имя учётной записи пустое или состоит из пробелов.</exception>
    /// <exception cref="ArgumentNullException">Если обработчик не задан.</exception>
    internal IDisposable Subscribe(string username, Action<RoleResolution> handler)
    {
        const string method = nameof(Subscribe);

        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException("Имя учётной записи не может быть пустым.", nameof(username));
        ArgumentNullException.ThrowIfNull(handler);

        string key = username.Trim();

        lock (_lock)
        {
            if (!_subscriptions.TryGetValue(key, out List<Action<RoleResolution>>? handlers))
            {
                handlers = [];
                _subscriptions[key] = handlers;
            }

            handlers.Add(handler);
        }

        Log.Debug(
            "Подписка на события смены роли пользователя. Class={Class}, Method={Method}",
            ClassName, method);

        return new Subscription(this, key, handler);
    }

    /// <summary>
    /// Рассылает новое состояние ролей пользователя его подписчикам и пишет
    /// событие в лог (аудит смены роли). Пустое имя, пустой список подписчиков
    /// или <see langword="null"/>-резолюция игнорируются; ошибка одного
    /// обработчика не мешает остальным и не роняет службу опроса.
    /// Решение о действии принимает подписчик: обновить клеймы роли либо
    /// выполнить принудительный выход (потеря группы Users —
    /// <see cref="RoleResolution.HasUsersGroup"/>).
    /// </summary>
    /// <param name="username">Имя учётной записи (sAMAccountName).</param>
    /// <param name="resolution">Новое состояние ролей пользователя.</param>
    internal void Notify(string username, RoleResolution? resolution)
    {
        const string method = nameof(Notify);

        try
        {
            if (string.IsNullOrWhiteSpace(username) || resolution is null)
            {
                return;
            }

            string key = username.Trim();

            Action<RoleResolution>[] handlers;

            lock (_lock)
            {
                handlers = _subscriptions.TryGetValue(key, out List<Action<RoleResolution>>? list)
                    ? [.. list]
                    : [];
            }

            if (handlers.Length == 0)
            {
                return;
            }

            // Аудит смены роли; реальное имя учётной записи в лог не попадает
            Log.Information(
                "Событие смены роли. Username={User}, NewRole={NewRole}, MatchedRoles={Matched}, HasUsersGroup={HasUsers}. Class={Class}, Method={Method}",
                "UserAccount",
                resolution.EffectiveRole.SystemName,
                string.Join(",", resolution.MatchedRoles.Select(role => role.SystemName)),
                resolution.HasUsersGroup,
                ClassName, method);

            foreach (Action<RoleResolution> handler in handlers)
            {
                try
                {
                    handler(resolution);
                }
                catch (Exception ex)
                {
                    // Ошибка одного подписчика не должна ронять службу опроса
                    // и мешать доставке остальным
                    Log.Error(
                        ex,
                        "Исключение в обработчике события смены роли. Class={Class}, Method={Method}",
                        ClassName, method);
                }
            }
        }
        catch (Exception ex)
        {
            // Защита рассылки от внешних сбоев (например, при логировании)
            Log.Error(
                ex,
                "Исключение при рассылке события смены роли. Class={Class}, Method={Method}",
                ClassName, method);
        }
    }

    /// <summary>
    /// Снимает подписку обработчика пользователя.
    /// </summary>
    /// <param name="username">Имя учётной записи (уже нормализовано при подписке).</param>
    /// <param name="handler">Обработчик, снятый с подписки.</param>
    private void Unsubscribe(string username, Action<RoleResolution> handler)
    {
        const string method = nameof(Unsubscribe);

        lock (_lock)
        {
            if (_subscriptions.TryGetValue(username, out List<Action<RoleResolution>>? handlers))
            {
                handlers.Remove(handler);

                if (handlers.Count == 0)
                {
                    _subscriptions.Remove(username);
                }
            }
        }

        Log.Debug(
            "Отписка от событий смены роли. Class={Class}, Method={Method}",
            ClassName, method);
    }

    /// <summary>
    /// Подписка, возвращаемая <see cref="Subscribe"/>: освобождение снимает
    /// конкретный обработчик конкретного пользователя.
    /// </summary>
    /// <param name="owner">Нотификатор, в котором зарегистрирована подписка.</param>
    /// <param name="username">Имя учётной записи (нормализовано при подписке).</param>
    /// <param name="handler">Обработчик, снимаемый при освобождении подписки.</param>
    private sealed class Subscription(RoleChangeNotifier owner, string username, Action<RoleResolution> handler) : IDisposable
    {
        public void Dispose()
        {
            owner.Unsubscribe(username, handler);
        }
    }
}
