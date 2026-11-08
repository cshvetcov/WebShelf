using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты защиты окна «Активация разрешения» от перебора ключей
/// (PermitActivationGuard): блокировка уже после первой неудачной проверки
/// пермита, эскалация длительности удвоением (15 с → 30 с → … → предел
/// 15 минут), сброс эскалации после окна тишины и успешной активации,
/// независимость IP, поведение при null-IP. Состояние хранится в памяти —
/// тесты выполняются на любой ОС; время управляется ручным TimeProvider
/// без реальных задержек.
/// </summary>
public class PermitActivationGuardTests : IDisposable
{
    /// <summary>Тестируемый экземпляр защиты (с ручным источником времени).</summary>
    private readonly PermitActivationGuard _guard;

    /// <summary>Ручной источник времени: старт — фиксированный момент, сдвигается вручную.</summary>
    private readonly ManualTimeProvider _time = new();

    public PermitActivationGuardTests()
    {
        _guard = new PermitActivationGuard(_time);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _guard.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// До любых неудачных проверок активация не заблокирована,
    /// остаток секунд равен нулю.
    /// </summary>
    [Fact]
    public void IsLocked_InitialState_NotLocked()
    {
        bool locked = _guard.IsLocked("10.0.0.1", out int remainingSeconds);

        Assert.False(locked);
        Assert.Equal(0, remainingSeconds);
    }

    /// <summary>
    /// Блокировка наступает уже после первой неудачной проверки пермита
    /// и длится базовые 15 секунд.
    /// </summary>
    [Fact]
    public void RecordFailure_FirstAttempt_LocksForBaseDuration()
    {
        int lockoutSeconds = _guard.RecordFailure("10.0.0.1");

        Assert.Equal(PermitActivationGuard.BaseLockoutSeconds, lockoutSeconds);
    }

    /// <summary>
    /// После неудачи IsLocked возвращает true и остаток секунд блокировки.
    /// </summary>
    [Fact]
    public void IsLocked_AfterFailure_ReturnsRemainingSeconds()
    {
        _guard.RecordFailure("10.0.0.1");
        _time.Advance(TimeSpan.FromSeconds(5));

        bool locked = _guard.IsLocked("10.0.0.1", out int remainingSeconds);

        Assert.True(locked);
        Assert.Equal(PermitActivationGuard.BaseLockoutSeconds - 5, remainingSeconds);
    }

    /// <summary>
    /// После окончания блокировки IsLocked возвращает false — активация
    /// снова разрешена.
    /// </summary>
    [Fact]
    public void IsLocked_AfterLockoutExpires_NotLocked()
    {
        _guard.RecordFailure("10.0.0.1");
        _time.Advance(TimeSpan.FromSeconds(PermitActivationGuard.BaseLockoutSeconds + 1));

        bool locked = _guard.IsLocked("10.0.0.1", out int remainingSeconds);

        Assert.False(locked);
        Assert.Equal(0, remainingSeconds);
    }

    /// <summary>
    /// Каждая следующая неудача удваивает длительность блокировки:
    /// 15 → 30 → 60 → 120 → 240 → 480 → 900 (предел 15 минут) → 900.
    /// Попытки идут сразу после окончания предыдущей блокировки —
    /// окно эскалации не истекает.
    /// </summary>
    [Fact]
    public void RecordFailure_EachNextFailure_DoublesDurationUpToLimit()
    {
        int[] expected =
        [
            PermitActivationGuard.BaseLockoutSeconds,
            30, 60, 120, 240, 480,
            PermitActivationGuard.MaxLockoutSeconds,
            PermitActivationGuard.MaxLockoutSeconds,
        ];

        foreach (int expectedSeconds in expected)
        {
            int actualSeconds = _guard.RecordFailure("10.0.0.1");
            Assert.Equal(expectedSeconds, actualSeconds);

            // блокировка истекает — следующая неудача возможна
            _time.Advance(TimeSpan.FromSeconds(actualSeconds));
        }
    }

    /// <summary>
    /// Если с последней неудачи прошло больше окна эскалации (15 минут),
    /// счётчик начинается заново — первая блокировка снова 15 секунд.
    /// </summary>
    [Fact]
    public void RecordFailure_AfterEscalationWindow_ResetsToBaseDuration()
    {
        _guard.RecordFailure("10.0.0.1");
        _time.Advance(TimeSpan.FromSeconds(PermitActivationGuard.BaseLockoutSeconds));
        int second = _guard.RecordFailure("10.0.0.1");
        Assert.Equal(30, second); // эскалация внутри окна

        _time.Advance(TimeSpan.FromMinutes(15) + TimeSpan.FromSeconds(1));
        int afterCalm = _guard.RecordFailure("10.0.0.1");

        Assert.Equal(PermitActivationGuard.BaseLockoutSeconds, afterCalm);
    }

    /// <summary>
    /// Попытка во время активной блокировки не учитывается и не продлевает
    /// её: возвращается остаток текущей блокировки, а не удвоенная длительность.
    /// </summary>
    [Fact]
    public void RecordFailure_WhileLocked_DoesNotExtendOrEscalate()
    {
        _guard.RecordFailure("10.0.0.1");
        _time.Advance(TimeSpan.FromSeconds(5));

        int remaining = _guard.RecordFailure("10.0.0.1");

        Assert.Equal(PermitActivationGuard.BaseLockoutSeconds - 5, remaining);
    }

    /// <summary>
    /// Успешная активация разрешения снимает активную блокировку.
    /// </summary>
    [Fact]
    public void RecordSuccess_ClearsActiveLockout()
    {
        _guard.RecordFailure("10.0.0.1");
        bool lockedBefore = _guard.IsLocked("10.0.0.1", out _);
        Assert.True(lockedBefore);

        _guard.RecordSuccess("10.0.0.1");

        bool lockedAfter = _guard.IsLocked("10.0.0.1", out int remainingSeconds);
        Assert.False(lockedAfter);
        Assert.Equal(0, remainingSeconds);
    }

    /// <summary>
    /// Успешная активация сбрасывает эскалацию: следующая неудача снова
    /// даёт базовую длительность.
    /// </summary>
    [Fact]
    public void RecordSuccess_ResetsEscalation()
    {
        _guard.RecordFailure("10.0.0.1");
        _time.Advance(TimeSpan.FromSeconds(PermitActivationGuard.BaseLockoutSeconds));
        int second = _guard.RecordFailure("10.0.0.1");
        Assert.Equal(30, second);

        _guard.RecordSuccess("10.0.0.1");
        int next = _guard.RecordFailure("10.0.0.1");

        Assert.Equal(PermitActivationGuard.BaseLockoutSeconds, next);
    }

    /// <summary>
    /// Состояния разных IP независимы: неудачи с одного адреса
    /// не блокируют другой.
    /// </summary>
    [Fact]
    public void RecordFailure_DifferentIps_IndependentStates()
    {
        _guard.RecordFailure("10.0.0.1");

        bool otherIpLocked = _guard.IsLocked("10.0.0.2", out int remainingSeconds);

        Assert.False(otherIpLocked);
        Assert.Equal(0, remainingSeconds);
    }

    /// <summary>
    /// Null и пустой IP не создают ключа учёта: попытки не блокируются.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void RecordFailure_NullOrEmptyIp_DoesNotLock(string? clientIp)
    {
        int result = _guard.RecordFailure(clientIp);

        Assert.Equal(0, result);
        Assert.False(_guard.IsLocked(clientIp, out int remainingSeconds));
        Assert.Equal(0, remainingSeconds);
    }

    /// <summary>
    /// Ключ учёта нечувствителен к окружающим пробелам IP-адреса.
    /// </summary>
    [Fact]
    public void RecordFailure_IpWithWhitespace_SharesState()
    {
        _guard.RecordFailure(" 10.0.0.1 ");

        bool locked = _guard.IsLocked("10.0.0.1", out _);

        Assert.True(locked);
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

        int result = _guard.RecordFailure("10.0.0.1");

        Assert.Equal(PermitActivationGuard.BaseLockoutSeconds, result);
        Assert.True(_guard.IsLocked("10.0.0.1", out _));
    }

    /// <summary>
    /// Ручной источник времени для детерминированных тестов эскалации:
    /// текущий момент (UTC) фиксируется и сдвигается вызовами
    /// <see cref="Advance"/> без реальных задержек.
    /// </summary>
    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        /// <summary>Сдвигает текущий момент вперёд на заданный интервал.</summary>
        internal void Advance(TimeSpan delta) => _now = _now.Add(delta);

        /// <inheritdoc />
        public override DateTimeOffset GetUtcNow() => _now;
    }
}
