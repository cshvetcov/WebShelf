using System.Collections.Concurrent;
using WebShelf.Classes.DC;

namespace WebShelf.Classes.Security;

/// <summary>
/// Вычисляет роль пользователя по прямым группам AD: вариант 1 — TTL-кэш,
/// вариант 3 — свежее вычисление в обход кэша (вход, критичные операции).
/// Источник истины — всегда AD; клейм роли в cookie — только транспорт
/// на момент входа. При недоступности AD отдаёт последнее известное значение
/// (stale-if-error); при отсутствии кэша — <see langword="null"/>
/// (вход в этом случае отклоняется — fail-secure).
/// Результат вычисления — <see cref="RoleResolution"/> (создаётся здесь
/// и в <see cref="RoleCatalog"/>, состав ролей берётся из каталога).
/// </summary>
internal sealed class RoleResolver
{
    private const string ClassName = "WebShelf.Classes.Security.RoleResolver";

    /// <summary>
    /// Запись кэша: результат вычисления и момент вычисления (UTC).
    /// Хранится и после истечения TTL — как последнее известное значение
    /// на случай сбоя AD.
    /// </summary>
    private sealed class CacheEntry
    {
        public CacheEntry(RoleResolution resolution, DateTimeOffset resolvedAtUtc)
        {
            Resolution = resolution;
            ResolvedAtUtc = resolvedAtUtc;
        }

        public RoleResolution Resolution { get; }

        public DateTimeOffset ResolvedAtUtc { get; }
    }

    private readonly IAdGroupSource _ad;
    private readonly RoleCacheOptions _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>Кэш по sAMAccountName (ключ без учёта регистра).</summary>
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Сериализация промахов кэша: исключает шторм запросов к AD при массовом истечении TTL.</summary>
    private readonly object _missLock = new();

    /// <summary>Расширенные имена ролевых групп → роли. Строится один раз в конструкторе.</summary>
    private readonly Dictionary<string, AppRole>? _roleGroups;

    /// <summary>Расширенное имя группы доступа Users.</summary>
    private readonly string? _usersGroupName;

    /// <summary>
    /// Конструктор объявлен <see langword="public"/> (сам класс остаётся internal):
    /// контейнер DI собирает зависимости только через public-конструктор,
    /// internal-конструктор контейнером не находится.
    /// </summary>
    public RoleResolver(IAdGroupSource adGroupSource, RoleCacheOptions options, TimeProvider timeProvider)
    {
        const string method = ".ctor";

        _ad = adGroupSource;
        _options = options;
        _timeProvider = timeProvider;

        // Карта групп строится заранее: суффиксы фиксированы каталогом ролей,
        // подстановка InstanceIdShort не требует обращения к AD.
        Dictionary<string, AppRole> map = new(StringComparer.OrdinalIgnoreCase);

        foreach (AppRole role in RoleCatalog.AdRoles)
        {
            if (role.GroupSuffix is null)
            {
                continue;
            }

            string? groupName = adGroupSource.GetExpandedGroupName(role.GroupSuffix);
            if (groupName is null)
            {
                Log.Error(
                    "Не удалось построить имя группы для роли {Role}. Class={Class}, Method={Method}",
                    role.SystemName, ClassName, method);
                _roleGroups = null;
                _usersGroupName = null;
                return;
            }

            map[groupName] = role;
        }

        string? usersGroupName = adGroupSource.GetExpandedGroupName(Domain.UsersGroupSuffix);
        if (usersGroupName is null)
        {
            Log.Error(
                "Не удалось построить имя группы Users. Class={Class}, Method={Method}",
                ClassName, method);
            _roleGroups = null;
            _usersGroupName = null;
            return;
        }

        _roleGroups = map;
        _usersGroupName = usersGroupName;

        Log.Debug(
            "Резолвер ролей инициализирован. RoleGroups={RoleGroups}, UsersGroup={UsersGroup}. Class={Class}, Method={Method}",
            map.Count, usersGroupName, ClassName, method);
    }

    /// <summary>
    /// Вариант 1: эффективная роль пользователя. В пределах TTL — из кэша
    /// без обращения к AD; при истечении — свежий запрос с обновлением кэша.
    /// При сбое AD возвращает последнее известное значение, если кэш есть.
    /// </summary>
    /// <param name="username">sAMAccountName (без доменной части).</param>
    /// <returns>Результат вычисления; <see langword="null"/> — AD недоступен и кэша нет.</returns>
    internal RoleResolution? Resolve(string username)
    {
        const string method = nameof(Resolve);

        if (string.IsNullOrWhiteSpace(username))
        {
            Log.Warning(
                "Пустое имя пользователя при вычислении роли. Class={Class}, Method={Method}",
                ClassName, method);
            return null;
        }

        try
        {
            string key = username.Trim();

            if (_cache.TryGetValue(key, out CacheEntry? hit) &&
                _timeProvider.GetUtcNow() - hit.ResolvedAtUtc <= _options.CacheTtl)
            {
                return hit.Resolution;
            }

            lock (_missLock)
            {
                // Повторная проверка после захвата: другой поток мог обновить кэш
                if (_cache.TryGetValue(key, out CacheEntry? raced) &&
                    _timeProvider.GetUtcNow() - raced.ResolvedAtUtc <= _options.CacheTtl)
                {
                    return raced.Resolution;
                }

                RoleResolution? fresh = ResolveCore(key, method);
                if (fresh is not null)
                {
                    return fresh;
                }

                // Сбой AD: отдаём устаревшее значение — лучше последнее известное,
                // чем отказ всей страницы; критичные операции идут через ResolveFresh
                if (_cache.TryGetValue(key, out CacheEntry? stale))
                {
                    Log.Warning(
                        "AD недоступен: выдано устаревшее значение роли (stale-if-error). Username={User}, AgeSec={Age}. Class={Class}, Method={Method}",
                        "UserAccount",
                        (int)(_timeProvider.GetUtcNow() - stale.ResolvedAtUtc).TotalSeconds,
                        ClassName, method);
                    return stale.Resolution;
                }

                return null;
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение при вычислении роли. Class={Class}, Method={Method}", ClassName, method);
            return null;
        }
    }

    /// <summary>
    /// Вариант 3: свежее вычисление в обход кэша — для входа, критичных операций
    /// и фонового опроса. Кэш обновляется результатом; при сбое AD кэш не трогается.
    /// </summary>
    /// <param name="username">sAMAccountName (без доменной части).</param>
    /// <returns>Результат вычисления; <see langword="null"/> — AD недоступен.</returns>
    internal RoleResolution? ResolveFresh(string username)
    {
        const string method = nameof(ResolveFresh);

        if (string.IsNullOrWhiteSpace(username))
        {
            Log.Warning(
                "Пустое имя пользователя при свежем вычислении роли. Class={Class}, Method={Method}",
                ClassName, method);
            return null;
        }

        try
        {
            return ResolveCore(username.Trim(), method);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение при свежем вычислении роли. Class={Class}, Method={Method}", ClassName, method);
            return null;
        }
    }

    /// <summary>
    /// Кэшированное значение без учёта TTL — для сравнения «до/после» в фоновом
    /// опросе. Кэш обновляется только через Resolve/ResolveFresh.
    /// </summary>
    /// <param name="username">sAMAccountName (без доменной части).</param>
    internal RoleResolution? Peek(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        return _cache.TryGetValue(username.Trim(), out CacheEntry? entry) ? entry.Resolution : null;
    }

    /// <summary>
    /// Пользователи, о которых резолверу известно (ключи кэша), — список
    /// для фонового опроса. Снимок на момент вызова.
    /// </summary>
    internal IReadOnlyList<string> GetTrackedUsernames()
    {
        List<string> usernames = _cache.Keys.ToList();
        return usernames;
    }

    /// <summary>
    /// Вычисление по текущим группам AD с записью результата в кэш.
    /// </summary>
    private RoleResolution? ResolveCore(string username, string method)
    {
        if (_roleGroups is null || _usersGroupName is null)
        {
            // Карта групп не построена — резолвер неработоспособен (причина уже в логе)
            Log.Error(
                "Карта ролевых групп не построена: вычисление невозможно. Class={Class}, Method={Method}",
                ClassName, method);
            return null;
        }

        IReadOnlyList<string>? groups = _ad.GetUserGroupNames(username);
        if (groups is null)
        {
            Log.Warning(
                "AD недоступен при вычислении роли. Username={User}. Class={Class}, Method={Method}",
                "UserAccount", ClassName, method);
            return null;
        }

        // Прямые группы пользователя → совпавшие роли
        HashSet<string> groupNames = new(groups, StringComparer.OrdinalIgnoreCase);
        List<AppRole> matched = [];

        foreach (KeyValuePair<string, AppRole> pair in _roleGroups)
        {
            if (groupNames.Contains(pair.Key))
            {
                matched.Add(pair.Value);
            }
        }

        // Несколько ролей — действует старшая (наименьший индекс старшинства);
        // список хранится по возрастанию старшинства
        matched.Sort((left, right) => left.SeniorityIndex - right.SeniorityIndex);
        AppRole effective = matched.Count == 0 ? RoleCatalog.Guest : matched[0];

        RoleResolution resolution = new RoleResolution(effective, matched, groupNames.Contains(_usersGroupName));
        _cache[username] = new CacheEntry(resolution, _timeProvider.GetUtcNow());

        return resolution;
    }
}
