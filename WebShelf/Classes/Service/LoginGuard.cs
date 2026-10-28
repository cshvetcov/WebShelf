using System.Collections.Concurrent;

namespace WebShelf.Classes.Service;

/// <summary>
/// Защита формы входа от перебора паролей (brute-force).
/// Учитывает неудачные попытки по IP-адресу клиента и по имени пользователя.
/// После <see cref="MaxFailedAttempts"/> ошибок вводит блокировку на <see cref="LockoutDuration"/>.
/// Хранилище — in-memory (подходит для одного экземпляра приложения).
/// </summary>
internal sealed class LoginGuard
{
    private const string ClassName = "WebShelf.Classes.Service.LoginGuard";

    /// <summary>Число неудачных попыток, после которого наступает блокировка.</summary>
    internal const int MaxFailedAttempts = 5;

    /// <summary>Длительность блокировки после превышения лимита попыток.</summary>
    internal static readonly TimeSpan LockoutDuration = TimeSpan.FromSeconds(30);

    /// <summary>Окно, в пределах которого считаются неудачные попытки.</summary>
    private static readonly TimeSpan AttemptWindow = TimeSpan.FromMinutes(15);

    private readonly ConcurrentDictionary<string, AttemptState> _states = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Проверяет, заблокирован ли вход для указанного IP и/или пользователя.
    /// </summary>
    /// <param name="clientIp">IP-адрес клиента.</param>
    /// <param name="username">Имя пользователя (может быть пустым до ввода).</param>
    /// <param name="remainingSeconds">Оставшиеся секунды блокировки (0, если не заблокирован).</param>
    /// <returns><see langword="true"/>, если вход временно запрещён.</returns>
    internal bool IsLocked(string? clientIp, string? username, out int remainingSeconds)
    {
        const string method = nameof(IsLocked);
        remainingSeconds = 0;

        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            int maxRemain = 0;

            foreach (string key in BuildKeys(clientIp, username))
            {
                if (!_states.TryGetValue(key, out AttemptState? state))
                    continue;

                if (state.LockedUntil is { } until && until > now)
                {
                    int sec = (int)Math.Ceiling((until - now).TotalSeconds);
                    if (sec > maxRemain)
                        maxRemain = sec;
                }
            }

            remainingSeconds = maxRemain;
            return maxRemain > 0;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            remainingSeconds = 0;
            return false;
        }
    }

    /// <summary>
    /// Фиксирует неудачную попытку входа. При достижении лимита устанавливает блокировку.
    /// </summary>
    /// <returns>Оставшиеся секунды блокировки (0, если блокировка ещё не наступила).</returns>
    internal int RecordFailure(string? clientIp, string? username)
    {
        const string method = nameof(RecordFailure);

        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            int maxRemain = 0;

            foreach (string key in BuildKeys(clientIp, username))
            {
                AttemptState state = _states.GetOrAdd(key, _ => new AttemptState());

                lock (state.Sync)
                {
                    // Сброс окна, если прошло слишком много времени
                    if (now - state.WindowStart > AttemptWindow)
                    {
                        state.Failures = 0;
                        state.WindowStart = now;
                        state.LockedUntil = null;
                    }

                    // Уже в блокировке — просто вернём остаток
                    if (state.LockedUntil is { } until && until > now)
                    {
                        int sec = (int)Math.Ceiling((until - now).TotalSeconds);
                        if (sec > maxRemain)
                            maxRemain = sec;
                        continue;
                    }

                    state.Failures++;
                    if (state.Failures == 1)
                        state.WindowStart = now;

                    if (state.Failures >= MaxFailedAttempts)
                    {
                        state.LockedUntil = now.Add(LockoutDuration);
                        state.Failures = 0; // после блокировки счётчик обнуляется
                        int sec = (int)Math.Ceiling(LockoutDuration.TotalSeconds);
                        if (sec > maxRemain)
                            maxRemain = sec;

                        // Не светим реальные имена учётных записей в логах
                        string logKey = key.StartsWith("user:", StringComparison.OrdinalIgnoreCase)
                            ? "user:UserAccount"
                            : key;
                        Log.Warning(
                            "Блокировка входа. Key={Key}, LockoutSeconds={Seconds}. Class={Class}, Method={Method}",
                            logKey, sec, ClassName, method);
                    }
                }
            }

            return maxRemain;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            return 0;
        }
    }

    /// <summary>
    /// Сбрасывает счётчики после успешного входа.
    /// </summary>
    internal void RecordSuccess(string? clientIp, string? username)
    {
        const string method = nameof(RecordSuccess);

        try
        {
            foreach (string key in BuildKeys(clientIp, username))
            {
                _states.TryRemove(key, out _);
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
        }
    }

    /// <summary>
    /// Формирует ключи учёта: по IP и по нормализованному имени пользователя.
    /// </summary>
    private static IEnumerable<string> BuildKeys(string? clientIp, string? username)
    {
        if (!string.IsNullOrWhiteSpace(clientIp))
            yield return "ip:" + clientIp.Trim();

        if (!string.IsNullOrWhiteSpace(username))
            yield return "user:" + username.Trim().ToLowerInvariant();
    }

    /// <summary>Состояние попыток для одного ключа (IP или пользователь).</summary>
    private sealed class AttemptState
    {
        internal readonly object Sync = new();
        internal int Failures;
        internal DateTimeOffset WindowStart = DateTimeOffset.UtcNow;
        internal DateTimeOffset? LockedUntil;
    }
}
