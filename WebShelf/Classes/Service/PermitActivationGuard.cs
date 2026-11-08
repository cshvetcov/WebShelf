using System.Collections.Concurrent;

namespace WebShelf.Classes.Service;

/// <summary>
/// Защита окна «Активация разрешения» от перебора ключей (brute-force).
/// Учитывает неудачные проверки пермита по IP-адресу клиента и блокирует
/// окно уже после первой неудачи; длительность каждой следующей блокировки
/// удваивается — от <see cref="BaseLockoutSeconds"/> до предела
/// <see cref="MaxLockoutSeconds"/> (15 минут).
/// Хранилище — in-memory singleton (как у <see cref="LoginGuard"/>): состояние
/// живёт на сервере, поэтому обновление страницы и разрыв цепи Blazor не сбрасывают
/// таймер — остаток блокировки дочитывается при открытии окна. Устаревшие
/// состояния периодически удаляются фоновым таймером, что исключает
/// неограниченный рост словаря при спаме уникальными IP.
/// </summary>
internal sealed class PermitActivationGuard : IDisposable
{
    private const string ClassName = "WebShelf.Classes.Service.PermitActivationGuard";

    /// <summary>Длительность первой блокировки, секунд.</summary>
    internal const int BaseLockoutSeconds = 15;

    /// <summary>Предел эскалации длительности блокировки — 15 минут, секунд.</summary>
    internal const int MaxLockoutSeconds = 15 * 60;

    /// <summary>
    /// Окно эскалации: если с последней неудачи прошло больше этого времени,
    /// счётчик блокировок начинается заново с первой (как AttemptWindow у LoginGuard).
    /// </summary>
    private static readonly TimeSpan EscalationWindow = TimeSpan.FromMinutes(15);

    /// <summary>Период фоновой очистки устаревших состояний.</summary>
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<string, PermitAttemptState> _states = new(StringComparer.OrdinalIgnoreCase);

    private readonly Timer _cleanupTimer;

    private bool _disposed;

    /// <summary>
    /// Источник текущего времени (UTC) для окна эскалации и блокировок.
    /// По умолчанию — <see cref="TimeProvider.System"/>; в юнит-тестах подменяется
    /// управляемым источником времени без ожидания реальных задержек.
    /// </summary>
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Создаёт экземпляр класса <see cref="PermitActivationGuard"/>
    /// и запускает фоновую очистку состояний.
    /// </summary>
    /// <param name="timeProvider">Источник времени для окна эскалации и блокировок;
    /// не задан (прямой вызов в тестах) — <see cref="TimeProvider.System"/>;
    /// при активации из DI внедряется зарегистрированный <see cref="TimeProvider"/>.</param>
    /// <remarks>
    /// Конструктор объявлен <see langword="public"/> (сам класс остаётся internal):
    /// тип регистрируется в контейнере DI через <c>AddSingleton&lt;PermitActivationGuard&gt;()</c>,
    /// а <c>Microsoft.Extensions.DependencyInjection</c> активирует сервисы только
    /// через public-конструктор — internal-конструктор контейнером не находится.
    /// </remarks>
    public PermitActivationGuard(TimeProvider? timeProvider = null)
    {
        const string method = ".ctor";

        _timeProvider = timeProvider ?? TimeProvider.System;
        _cleanupTimer = new Timer(RemoveStaleStates, null, CleanupInterval, CleanupInterval);

        Log.Information(
            "PermitActivationGuard инициализирован: запущена фоновая очистка состояний. BaseLockout={BaseLockout}, MaxLockout={MaxLockout}, EscalationWindow={Window}, CleanupInterval={CleanupInterval}. Class={Class}, Method={Method}",
            BaseLockoutSeconds, MaxLockoutSeconds, EscalationWindow, CleanupInterval, ClassName, method);
    }

    /// <summary>
    /// Проверяет, заблокирована ли активация разрешения для указанного IP-клиента.
    /// Вызывается при открытии окна «Активация разрешения» (восстановление остатка
    /// после обновления страницы) и перед проверкой пермита.
    /// </summary>
    /// <param name="clientIp">IP-адрес клиента.</param>
    /// <param name="remainingSeconds">Оставшиеся секунды блокировки (0, если не заблокирована).</param>
    /// <returns><see langword="true"/>, если активация временно запрещена.</returns>
    internal bool IsLocked(string? clientIp, out int remainingSeconds)
    {
        const string method = nameof(IsLocked);
        remainingSeconds = 0;

        try
        {
            if (BuildKey(clientIp) is not { } key)
                return false;

            if (!_states.TryGetValue(key, out PermitAttemptState? state))
                return false;

            DateTimeOffset now = _timeProvider.GetUtcNow();

            lock (state.Sync)
            {
                if (state.LockedUntil is { } until && until > now)
                {
                    remainingSeconds = (int)Math.Ceiling((until - now).TotalSeconds);
                    return true;
                }
            }

            return false;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            remainingSeconds = 0;
            return false;
        }
    }

    /// <summary>
    /// Фиксирует неудачную проверку пермита: блокирует активацию уже после первой
    /// неудачи с эскалацией длительности — каждая следующая блокировка вдвое дольше
    /// (от <see cref="BaseLockoutSeconds"/> до <see cref="MaxLockoutSeconds"/>),
    /// пока неудачи идут одна за другой в пределах окна эскалации.
    /// Попытка во время активной блокировки не учитывается и не продлевает её.
    /// </summary>
    /// <param name="clientIp">IP-адрес клиента.</param>
    /// <returns>Длительность установленной блокировки, секунд (остаток активной —
    /// если блокировка уже была; 0 — если ключ учёта не построен).</returns>
    internal int RecordFailure(string? clientIp)
    {
        const string method = nameof(RecordFailure);

        try
        {
            if (BuildKey(clientIp) is not { } key)
                return 0;

            DateTimeOffset now = _timeProvider.GetUtcNow();

            PermitAttemptState state = _states.GetOrAdd(key, _ => new PermitAttemptState(_timeProvider));

            lock (state.Sync)
            {
                // Уже в блокировке — попытка не учитывается, остаток не меняется
                if (state.LockedUntil is { } until && until > now)
                    return (int)Math.Ceiling((until - now).TotalSeconds);

                // Окно эскалации истекло — серия неудач начинается заново
                if (now - state.WindowStart > EscalationWindow)
                    state.LockoutNumber = 0;

                state.LockoutNumber++;
                state.WindowStart = now;

                int seconds = GetLockoutSeconds(state.LockoutNumber);
                state.LockedUntil = now.AddSeconds(seconds);

                Log.Warning(
                    "Блокировка активации разрешения. Key={Key}, LockoutNumber={LockoutNumber}, LockoutSeconds={Seconds}. Class={Class}, Method={Method}",
                    key, state.LockoutNumber, seconds, ClassName, method);

                return seconds;
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
            return 0;
        }
    }

    /// <summary>
    /// Сбрасывает состояние после успешной активации разрешения (действующий пермит):
    /// активная блокировка снимается, эскалация начинается заново.
    /// </summary>
    /// <param name="clientIp">IP-адрес клиента.</param>
    internal void RecordSuccess(string? clientIp)
    {
        const string method = nameof(RecordSuccess);

        try
        {
            if (BuildKey(clientIp) is not { } key)
                return;

            _states.TryRemove(key, out _);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
        }
    }

    /// <summary>
    /// Вычисляет длительность блокировки с учётом эскалации: первая —
    /// <see cref="BaseLockoutSeconds"/>, каждая следующая — вдвое дольше,
    /// но не более <see cref="MaxLockoutSeconds"/> (как GetLockoutDuration у LoginGuard).
    /// </summary>
    /// <param name="lockoutNumber">Порядковый номер блокировки в окне эскалации (от 1).</param>
    private static int GetLockoutSeconds(int lockoutNumber)
    {
        // Ограничиваем степень двойки, чтобы избежать переполнения double
        int exponent = Math.Min(Math.Max(lockoutNumber - 1, 0), 16);
        double seconds = BaseLockoutSeconds * Math.Pow(2, exponent);
        return (int)Math.Min(seconds, MaxLockoutSeconds);
    }

    /// <summary>
    /// Фоновая очистка: удаляет состояния, чьё окно эскалации истекло
    /// и которые не находятся в активной блокировке.
    /// Защищает словарь от неограниченного роста при спаме уникальными IP.
    /// </summary>
    /// <param name="state">Служебный параметр таймера (не используется).</param>
    private void RemoveStaleStates(object? state)
    {
        const string method = nameof(RemoveStaleStates);

        try
        {
            DateTimeOffset now = _timeProvider.GetUtcNow();
            int removed = 0;

            foreach (KeyValuePair<string, PermitAttemptState> pair in _states)
            {
                bool isStale = false;

                lock (pair.Value.Sync)
                {
                    bool isLocked = pair.Value.LockedUntil is { } until && until > now;
                    isStale = !isLocked && (now - pair.Value.WindowStart) > EscalationWindow;
                }

                if (isStale && _states.TryRemove(pair.Key, out _))
                {
                    removed++;
                }
            }

            if (removed > 0)
            {
                Log.Debug(
                    "Очистка устаревших состояний PermitActivationGuard. Removed={Removed}, Remaining={Remaining}. Class={Class}, Method={Method}",
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

            Log.Debug("PermitActivationGuard остановлен. Class={Class}, Method={Method}", ClassName, method);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Исключение в {Class}.{Method}", ClassName, method);
        }
    }

    /// <summary>
    /// Строит ключ учёта по IP-адресу клиента. Учёт ведётся только по IP:
    /// у окна активации нет имени пользователя (как у формы входа), ключом
    /// перебора может стать любой посетитель с этого адреса.
    /// </summary>
    /// <returns>Ключ вида <c>ip:…</c> или <see langword="null"/>, если адрес не задан.</returns>
    private static string? BuildKey(string? clientIp)
        => string.IsNullOrWhiteSpace(clientIp) ? null : "ip:" + clientIp.Trim();

    /// <summary>Состояние неудачных проверок пермита для одного IP.</summary>
    /// <param name="timeProvider">Источник времени — момент начала окна эскалации.</param>
    private sealed class PermitAttemptState(TimeProvider timeProvider)
    {
        /// <summary>Блокировка доступа к состоянию (C# 13 <see cref="Lock"/> —
        /// специализированный тип блокировки вместо <c>object</c>).</summary>
        internal readonly Lock Sync = new();

        /// <summary>Начало текущего окна эскалации (время последней неудачи).</summary>
        internal DateTimeOffset WindowStart = timeProvider.GetUtcNow();

        /// <summary>Момент окончания активной блокировки (если установлена).</summary>
        internal DateTimeOffset? LockedUntil;

        /// <summary>Порядковый номер последней блокировки (для эскалации длительности).</summary>
        internal int LockoutNumber;
    }
}
