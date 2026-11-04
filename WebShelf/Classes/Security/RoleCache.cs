namespace WebShelf.Classes.Security;

/// <summary>
/// Кэш вычисленных ролей пользователей с TTL (временем жизни записи).
/// Потокобезопасен. Имена учётных записей сравниваются без учёта регистра
/// (sAMAccountName в AD регистронезависим). Часы внедряются делегатом —
/// это позволяет управлять временем в юнит-тестах без ожидания реальных задержек.
/// </summary>
internal sealed class RoleCache
{
    private readonly object _lock = new();

    /// <summary>
    /// Записи кэша: имя учётной записи → результат вычисления роли и момент его получения.
    /// </summary>
    private readonly Dictionary<string, RoleCacheEntry> _entries = new(StringComparer.OrdinalIgnoreCase);

    private readonly TimeSpan _ttl;

    private readonly Func<DateTimeOffset> _clock;

    /// <summary>
    /// Создаёт кэш с указанным временем жизни записей.
    /// </summary>
    /// <param name="ttl">Время жизни записи; значения <see langword="TimeSpan.Zero"/> и отрицательные не допускаются.</param>
    /// <param name="clock">
    /// Функция текущего времени (UTC). По умолчанию — <see cref="DateTimeOffset.UtcNow"/>;
    /// в тестах подменяется управляемым источником времени.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException">Если TTL не положительный.</exception>
    internal RoleCache(TimeSpan ttl, Func<DateTimeOffset>? clock = null)
    {
        if (ttl <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(ttl), "TTL кэша роли должен быть положительным.");

        _ttl = ttl;
        _clock = clock ?? (static () => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Возвращает запись кэша, если она существует и не истекла по TTL.
    /// Истёкшая запись не удаляется: <see cref="TryPeek"/> сохраняет последнюю
    /// известную роль для сравнения с новым результатом (обнаружение изменения роли
    /// при истечении TTL), а перезапись выполняется методом <see cref="Set"/>.
    /// </summary>
    /// <param name="samAccountName">Имя учётной записи (sAMAccountName).</param>
    /// <param name="resolution">Результат вычисления роли, если запись найдена и актуальна.</param>
    /// <returns><see langword="true"/>, если найдена актуальная запись; иначе — <see langword="false"/>.</returns>
    internal bool TryGet(string samAccountName, out RoleResolution resolution)
    {
        lock (_lock)
        {
            if (!_entries.TryGetValue(samAccountName, out RoleCacheEntry? entry)
                || _clock() - entry.AcquiredUtc >= _ttl)
            {
                resolution = null!;
                return false;
            }

            resolution = entry.Resolution;
            return true;
        }
    }

    /// <summary>
    /// Возвращает запись кэша, если она существует, — в том числе уже истёкшую по TTL
    /// (запись не удаляется при истечении, а перезаписывается методом <see cref="Set"/>).
    /// Используется для сравнения с новым результатом (обнаружение изменения роли),
    /// когда важна последняя известная роль, а не её актуальность.
    /// </summary>
    /// <param name="samAccountName">Имя учётной записи (sAMAccountName).</param>
    /// <param name="resolution">Последний известный результат вычисления роли.</param>
    /// <returns><see langword="true"/>, если запись найдена (в том числе истёкшая).</returns>
    internal bool TryPeek(string samAccountName, out RoleResolution resolution)
    {
        lock (_lock)
        {
            if (_entries.TryGetValue(samAccountName, out RoleCacheEntry? entry))
            {
                resolution = entry.Resolution;
                return true;
            }

            resolution = null!;
            return false;
        }
    }

    /// <summary>
    /// Сохраняет результат вычисления роли с текущей меткой времени.
    /// </summary>
    /// <param name="samAccountName">Имя учётной записи (sAMAccountName).</param>
    /// <param name="resolution">Результат вычисления роли.</param>
    internal void Set(string samAccountName, RoleResolution resolution)
    {
        ArgumentNullException.ThrowIfNull(resolution);

        lock (_lock)
        {
            _entries[samAccountName] = new RoleCacheEntry(resolution, _clock());
        }
    }

    /// <summary>
    /// Удаляет запись кэша, если она существует.
    /// </summary>
    /// <param name="samAccountName">Имя учётной записи (sAMAccountName).</param>
    /// <returns><see langword="true"/>, если запись существовала и удалена.</returns>
    internal bool Remove(string samAccountName)
    {
        lock (_lock)
        {
            return _entries.Remove(samAccountName);
        }
    }

    /// <summary>
    /// Запись кэша: результат вычисления роли и момент его получения.
    /// </summary>
    private sealed record RoleCacheEntry(RoleResolution Resolution, DateTimeOffset AcquiredUtc);
}
