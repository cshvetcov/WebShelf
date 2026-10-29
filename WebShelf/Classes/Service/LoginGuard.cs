using System.Collections.Concurrent;

namespace WebShelf.Classes.Service;

/// <summary>
/// Защита формы входа от перебора паролей (brute-force).
/// Учитывает неудачные попытки по IP-адресу клиента и по имени пользователя.
/// После <see cref="MaxFailedAttempts"/> ошибок вводит блокировку; длительность
/// каждой следующей блокировки удваивается (от <see cref="BaseLockoutDuration"/>
/// до <see cref="MaxLockoutDuration"/>).
/// Хранилище — in-memory (подходит для одного экземпляра приложения);
/// устаревшие состояния периодически удаляются фоновым таймером,
/// что исключает неограниченный рост словаря при спаме уникальными ключами.
/// </summary>
internal sealed class LoginGuard : IDisposable
{
    private const string ClassName = "WebShelf.Classes.Service.LoginGuard";

    /// <summary>Число неудачных попыток, после которого наступает блокировка.</summary>
    internal const int MaxFailedAttempts = 5;

    /// <summary>Окно, в пределах которого считаются неудачные попытки.</summary>
    private static readonly TimeSpan AttemptWindow = TimeSpan.FromMinutes(15);

    /// <summary>Базовая (первая) длительность блокировки.</summary>
    private static readonly TimeSpan BaseLockoutDuration = TimeSpan.FromSeconds(30);

    /// <summary>Максимальная длительность блокировки — потолок эскалации.</summary>
    private static readonly TimeSpan MaxLockoutDuration = TimeSpan.FromMinutes(15);

    /// <summary>Период фоновой очистки устаревших состояний.</summary>
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<string, AttemptState> _states = new(StringComparer.OrdinalIgnoreCase);

    private readonly Timer _cleanupTimer;

    private bool _disposed;

    /// <summary>
    /// Создаёт экземпляр класса <see cref="LoginGuard"/>
    /// и запускает фоновую очистку устаревших состояний.
    /// </summary>
    /// <remarks>
    /// Конструктор объявлен <see langword="public"/> (сам класс остаётся internal):
    /// тип регистрируется в контейнере DI через <c>AddSingleton&lt;LoginGuard&gt;()</c>,
    /// а <c>Microsoft.Extensions.DependencyInjection</c> активирует сервисы только
    /// через public-конструктор — internal-конструктор контейнером не находится.
    /// </remarks>
    public LoginGuard()
    {
        const string method = ".ctor";

        _cleanupTimer = new Timer(RemoveStaleStates, null, CleanupInterval, CleanupInterval);

        Log.Information(
            "LoginGuard инициализирован: запущена фоновая очистка состояний. AttemptWindow={Window}, BaseLockout={BaseLockout}, MaxLockout={MaxLockout}, MaxFailedAttempts={MaxFailed}, CleanupInterval={CleanupInterval}. Class={Class}, Method={Method}",
            AttemptWindow, BaseLockoutDuration, MaxLockoutDuration, MaxFailedAttempts, CleanupInterval, ClassName, method);
    }

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
    /// Фиксирует неудачную попытку входа. При достижении лимита устанавливает
    /// блокировку с эскалацией длительности (удвоение за каждое повторное
    /// срабатывание в пределах окна попыток).
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
                        state.LockoutNumber = 0;
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
                        state.LockoutNumber++;

                        TimeSpan lockoutDuration = GetLockoutDuration(state.LockoutNumber);
                        state.LockedUntil = now.Add(lockoutDuration);
                        state.Failures = 0; // после блокировки счётчик обнуляется

                        int sec = (int)Math.Ceiling(lockoutDuration.TotalSeconds);
                        if (sec > maxRemain)
                            maxRemain = sec;

                        // Не светим реальные имена учётных записей в логах
                        string logKey = key.StartsWith("user:", StringComparison.OrdinalIgnoreCase)
                            ? "user:UserAccount"
                            : key;
                        Log.Warning(
                            "Блокировка входа. Key={Key}, LockoutNumber={LockoutNumber}, LockoutSeconds={Seconds}. Class={Class}, Method={Method}",
                            logKey, state.LockoutNumber, sec, ClassName, method);
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
    /// Вычисляет длительность блокировки с учётом эскалации:
    /// первая — <see cref="BaseLockoutDuration"/>, каждая следующая — вдвое дольше,
    /// но не более <see cref="MaxLockoutDuration"/>.
    /// </summary>
    /// <param name="lockoutNumber">Порядковый номер блокировки в окне попыток (от 1).</param>
    private static TimeSpan GetLockoutDuration(int lockoutNumber)
    {
        // Ограничиваем степень двойки, чтобы избежать переполнения double
        int exponent = Math.Min(Math.Max(lockoutNumber - 1, 0), 16);
        double seconds = BaseLockoutDuration.TotalSeconds * Math.Pow(2, exponent);
        return TimeSpan.FromSeconds(Math.Min(seconds, MaxLockoutDuration.TotalSeconds));
    }

    /// <summary>
    /// Фоновая очистка: удаляет состояния, чьё окно попыток истекло
    /// и которые не находятся в активной блокировке.
    /// Защищает словарь от неограниченного роста при спаме уникальными ключами.
    /// </summary>
    /// <param name="state">Служебный параметр таймера (не используется).</param>
    private void RemoveStaleStates(object? state)
    {
        const string method = nameof(RemoveStaleStates);

        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            int removed = 0;

            foreach (KeyValuePair<string, AttemptState> pair in _states)
            {
                bool isStale = false;

                lock (pair.Value.Sync)
                {
                    bool isLocked = pair.Value.LockedUntil is { } until && until > now;
                    isStale = !isLocked && (now - pair.Value.WindowStart) > AttemptWindow;
                }

                if (isStale && _states.TryRemove(pair.Key, out _))
                {
                    removed++;
                }
            }

            if (removed > 0)
            {
                Log.Debug(
                    "Очистка устаревших состояний LoginGuard. Removed={Removed}, Remaining={Remaining}. Class={Class}, Method={Method}",
                    removed, _states.Count, ClassName, method);
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
        }
    }

    /// <summary>
    /// Останавливает фоновую очистку. Вызывается контейнером DI
    /// при завершении работы приложения.
    /// </summary>
    public void Dispose()
    {
        const string method = nameof(Dispose);

        try
        {
            if (_disposed)
                return;

            _disposed = true;
            _cleanupTimer.Dispose();

            Log.Debug("LoginGuard остановлен. Class={Class}, Method={Method}", ClassName, method);
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
        /// <summary>Объект синхронизации доступа к состоянию.</summary>
        internal readonly object Sync = new();

        /// <summary>Число неудачных попыток в текущем окне.</summary>
        internal int Failures;

        /// <summary>Начало текущего окна попыток.</summary>
        internal DateTimeOffset WindowStart = DateTimeOffset.UtcNow;

        /// <summary>Момент окончания активной блокировки (если установлена).</summary>
        internal DateTimeOffset? LockedUntil;

        /// <summary>Порядковый номер последней блокировки (для эскалации длительности).</summary>
        internal int LockoutNumber;
    }
}
