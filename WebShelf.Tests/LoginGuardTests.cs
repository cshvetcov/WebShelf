using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты защиты от перебора паролей LoginGuard: блокировка по IP и по пользователю,
/// эскалация, сброс после успешного входа, регистронезависимость и чистка ключей.
/// Состояние хранится в памяти — тесты выполняются на любой ОС.
/// </summary>
public class LoginGuardTests : IDisposable
{
    /// <summary>Тестируемый экземпляр защиты.</summary>
    private readonly LoginGuard _guard = new LoginGuard();

    /// <inheritdoc />
    public void Dispose()
    {
        _guard.Dispose();
    }

    /// <summary>Фиксирует указанное число неудачных попыток и возвращает результат последней.</summary>
    private static int RecordFailures(LoginGuard guard, string? ip, string? username, int count)
    {
        int result = 0;
        for (int i = 0; i < count; i++)
        {
            result = guard.RecordFailure(ip, username);
        }

        return result;
    }

    /// <summary>
    /// До любых неудачных попыток вход не заблокирован, остаток секунд равен нулю.
    /// </summary>
    [Fact]
    public void IsLocked_InitialState_NotLocked()
    {
        bool locked = _guard.IsLocked("10.0.0.1", "ivanov", out int remainingSeconds);

        Assert.False(locked);
        Assert.Equal(0, remainingSeconds);
    }

    /// <summary>
    /// Блокировка наступает ровно после MaxFailedAttempts неудачных попыток;
    /// первая блокировка длится BaseLockoutDuration (30 секунд).
    /// </summary>
    [Fact]
    public void RecordFailure_AtMaxFailedAttempts_LocksForBaseDuration()
    {
        int before = RecordFailures(_guard, "10.0.0.1", "ivanov", LoginGuard.MaxFailedAttempts - 1);
        Assert.Equal(0, before);

        int lockoutSeconds = _guard.RecordFailure("10.0.0.1", "ivanov");

        Assert.InRange(lockoutSeconds, 29, 30); // базовая блокировка — 30 секунд
    }

    /// <summary>
    /// После блокировки IsLocked возвращает true и остаток секунд.
    /// </summary>
    [Fact]
    public void IsLocked_AfterLockout_ReturnsRemainingSeconds()
    {
        RecordFailures(_guard, "10.0.0.1", "ivanov", LoginGuard.MaxFailedAttempts);

        bool locked = _guard.IsLocked("10.0.0.1", "ivanov", out int remainingSeconds);

        Assert.True(locked);
        Assert.InRange(remainingSeconds, 1, 30);
    }

    /// <summary>
    /// Неудачные попытки во время активной блокировки не продлевают её:
    /// счётчик не растёт, LockedUntil не сдвигается.
    /// </summary>
    [Fact]
    public void RecordFailure_WhileLocked_DoesNotExtendLockout()
    {
        RecordFailures(_guard, "10.0.0.1", "ivanov", LoginGuard.MaxFailedAttempts);
        bool locked = _guard.IsLocked("10.0.0.1", "ivanov", out int firstRemaining);
        Assert.True(locked);

        int secondRemaining = _guard.RecordFailure("10.0.0.1", "ivanov");
        int thirdRemaining = _guard.RecordFailure("10.0.0.1", "ivanov");

        Assert.Equal(firstRemaining, secondRemaining);
        Assert.Equal(firstRemaining, thirdRemaining);
    }

    /// <summary>
    /// Успешный вход снимает активную блокировку.
    /// </summary>
    [Fact]
    public void RecordSuccess_ClearsActiveLockout()
    {
        RecordFailures(_guard, "10.0.0.1", "ivanov", LoginGuard.MaxFailedAttempts);
        bool lockedBefore = _guard.IsLocked("10.0.0.1", "ivanov", out _);
        Assert.True(lockedBefore);

        _guard.RecordSuccess("10.0.0.1", "ivanov");

        bool lockedAfter = _guard.IsLocked("10.0.0.1", "ivanov", out int remainingSeconds);
        Assert.False(lockedAfter);
        Assert.Equal(0, remainingSeconds);
    }

    /// <summary>
    /// Успешный вход сбрасывает счётчик неудач: следующая серия начинается с нуля.
    /// </summary>
    [Fact]
    public void RecordSuccess_ResetsFailureCounter()
    {
        RecordFailures(_guard, "10.0.0.1", "ivanov", 3);
        _guard.RecordSuccess("10.0.0.1", "ivanov");

        int result = RecordFailures(_guard, "10.0.0.1", "ivanov", LoginGuard.MaxFailedAttempts - 1);

        Assert.Equal(0, result); // 4 новых попытки после сброса не блокируют
    }

    /// <summary>
    /// Счётчики разных пользователей независимы: неудачи Alice не блокируют Bob
    /// и не блокируют Alice с другого IP, если сработал только пользовательский ключ.
    /// </summary>
    [Fact]
    public void RecordFailure_DifferentUsers_IndependentCounters()
    {
        RecordFailures(_guard, "10.0.0.1", "alice", LoginGuard.MaxFailedAttempts - 1);

        // Bob с тем же IP не заблокирован (его пользовательский ключ пуст)
        bool bobLocked = _guard.IsLocked("10.0.0.1", "bob", out int bobRemaining);
        Assert.False(bobLocked);
        Assert.Equal(0, bobRemaining);

        RecordFailures(_guard, "10.0.0.1", "alice", 1);

        // Alice заблокирована по пользовательскому ключу — в том числе с другого IP
        bool aliceLockedFromOtherIp = _guard.IsLocked("10.0.0.2", "alice", out int aliceRemaining);
        Assert.True(aliceLockedFromOtherIp);
        Assert.InRange(aliceRemaining, 1, 30);
    }

    /// <summary>
    /// Счётчики разных IP независимы: серия неудач с одного IP не блокирует другой IP.
    /// </summary>
    [Fact]
    public void RecordFailure_DifferentIps_IndependentCounters()
    {
        RecordFailures(_guard, "10.0.0.1", "user1", LoginGuard.MaxFailedAttempts);

        bool otherIpLocked = _guard.IsLocked("10.0.0.2", "user2", out int remainingSeconds);

        Assert.False(otherIpLocked);
        Assert.Equal(0, remainingSeconds);
    }

    /// <summary>
    /// Блокировка по IP действует на любого пользователя с этого IP.
    /// </summary>
    [Fact]
    public void RecordFailure_LockedIp_AppliesToAnyUser()
    {
        RecordFailures(_guard, "10.0.0.1", "user1", LoginGuard.MaxFailedAttempts);

        bool locked = _guard.IsLocked("10.0.0.1", "user2", out int remainingSeconds);

        Assert.True(locked);
        Assert.InRange(remainingSeconds, 1, 30);
    }

    /// <summary>
    /// Учёт попыток регистронезависим и нечувствителен к окружающим пробелам.
    /// </summary>
    [Fact]
    public void RecordFailure_CaseAndWhitespaceInsensitive_SharesCounter()
    {
        RecordFailures(_guard, "10.0.0.1", " Alice ", LoginGuard.MaxFailedAttempts);

        bool locked = _guard.IsLocked("10.0.0.1", "alice", out _);

        Assert.True(locked);
    }

    /// <summary>
    /// Null-IP и null-имя пользователя не создают ключей учёта
    /// и никогда не приводят к блокировке.
    /// </summary>
    [Fact]
    public void RecordFailure_NullIpAndNullUsername_DoesNotLock()
    {
        int result = RecordFailures(_guard, null, null, LoginGuard.MaxFailedAttempts * 2);

        Assert.Equal(0, result);
        Assert.False(_guard.IsLocked(null, null, out int remainingSeconds));
        Assert.Equal(0, remainingSeconds);
    }

    /// <summary>
    /// Null-IP с указанным именем пользователя: учёт ведётся по пользовательскому ключу.
    /// </summary>
    [Fact]
    public void RecordFailure_NullIp_UsesUserKeyOnly()
    {
        RecordFailures(_guard, null, "alice", LoginGuard.MaxFailedAttempts);

        bool lockedByUser = _guard.IsLocked(null, "alice", out _);
        bool lockedByIp = _guard.IsLocked("10.0.0.1", null, out _);

        Assert.True(lockedByUser);
        Assert.False(lockedByIp);
    }

    /// <summary>
    /// Пустое имя пользователя трактуется как отсутствие пользовательского ключа:
    /// блокируется только IP-ключ.
    /// </summary>
    [Fact]
    public void RecordFailure_EmptyUsername_UsesIpKeyOnly()
    {
        RecordFailures(_guard, "10.0.0.1", string.Empty, LoginGuard.MaxFailedAttempts);

        bool lockedByIp = _guard.IsLocked("10.0.0.1", string.Empty, out _);
        bool lockedWithoutKeys = _guard.IsLocked(null, string.Empty, out _);

        Assert.True(lockedByIp);
        Assert.False(lockedWithoutKeys);
    }

    /// <summary>
    /// Повторный Dispose не выбрасывает исключений (идемпотентность).
    /// </summary>
    [Fact]
    public void Dispose_CalledTwice_DoesNotThrow()
    {
        _guard.Dispose();
        _guard.Dispose();
    }

    /// <summary>
    /// Методы после Dispose продолжают работать без исключений
    /// (состояние в памяти, фоновый таймер остановлен).
    /// </summary>
    [Fact]
    public void Methods_AfterDispose_DoesNotThrow()
    {
        _guard.Dispose();

        int result = _guard.RecordFailure("10.0.0.1", "ivanov");

        Assert.Equal(0, result);
        Assert.False(_guard.IsLocked("10.0.0.1", "ivanov", out _));
    }
}
