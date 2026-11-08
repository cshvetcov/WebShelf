using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты логики обратного отсчёта блокировки (CountdownLockout): запуск,
/// тики, снятие блокировки по нулю, перезапуск. Тесты чистые — таймер
/// принадлежит владельцу класса (страница /entry), здесь проверяется
/// только логика состояния.
/// </summary>
public class CountdownLockoutTests
{
    /// <summary>
    /// Исходное состояние: блокировка не активна, остаток — ноль.
    /// </summary>
    [Fact]
    public void InitialState_NotLocked()
    {
        CountdownLockout lockout = new();

        Assert.False(lockout.IsLocked);
        Assert.Equal(0, lockout.RemainingSeconds);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void Start_NonPositiveSeconds_DoesNotLock(int seconds)
    {
        CountdownLockout lockout = new();

        lockout.Start(seconds);

        Assert.False(lockout.IsLocked);
        Assert.Equal(0, lockout.RemainingSeconds);
    }

    /// <summary>
    /// Запуск блокировки на 15 секунд (сценарий кнопки «Зарегистрироваться»).
    /// </summary>
    [Fact]
    public void Start_PositiveSeconds_LocksWithCountdown()
    {
        CountdownLockout lockout = new();

        lockout.Start(15);

        Assert.True(lockout.IsLocked);
        Assert.Equal(15, lockout.RemainingSeconds);
    }

    /// <summary>
    /// Каждый тик уменьшает остаток на одну секунду.
    /// </summary>
    [Fact]
    public void Tick_DecrementsRemainingSeconds()
    {
        CountdownLockout lockout = new();
        lockout.Start(15);

        lockout.Tick();

        Assert.True(lockout.IsLocked);
        Assert.Equal(14, lockout.RemainingSeconds);
    }

    /// <summary>
    /// Полный отсчёт 15 секунд: блокировка снимается ровно на 15-м тике.
    /// </summary>
    [Fact]
    public void Tick_FullCountdown_UnlocksAtZero()
    {
        CountdownLockout lockout = new();
        lockout.Start(15);

        for (int tick = 0; tick < 15; tick++)
        {
            Assert.True(lockout.IsLocked, $"Блокировка не должна сниматься до тика {tick + 1}");
            lockout.Tick();
        }

        Assert.False(lockout.IsLocked);
        Assert.Equal(0, lockout.RemainingSeconds);
    }

    /// <summary>
    /// Тики после снятия блокировки не уводят остаток ниже нуля.
    /// </summary>
    [Fact]
    public void Tick_AfterUnlocked_RemainsZero()
    {
        CountdownLockout lockout = new();
        lockout.Start(2);
        lockout.Tick();
        lockout.Tick();
        lockout.Tick();
        lockout.Tick();

        Assert.False(lockout.IsLocked);
        Assert.Equal(0, lockout.RemainingSeconds);
    }

    /// <summary>
    /// Повторный запуск отсчёта перезапускает его заново
    /// (новая неудачная проверка пермита во время блокировки).
    /// </summary>
    [Fact]
    public void Start_WhileCountingDown_RestartsCountdown()
    {
        CountdownLockout lockout = new();
        lockout.Start(15);

        for (int tick = 0; tick < 5; tick++)
        {
            lockout.Tick();
        }

        Assert.Equal(10, lockout.RemainingSeconds);

        lockout.Start(15);

        Assert.True(lockout.IsLocked);
        Assert.Equal(15, lockout.RemainingSeconds);
    }

    /// <summary>
    /// Тики до запуска (блокировка не активна) не меняют состояние.
    /// </summary>
    [Fact]
    public void Tick_BeforeStart_NoEffect()
    {
        CountdownLockout lockout = new();

        lockout.Tick();

        Assert.False(lockout.IsLocked);
        Assert.Equal(0, lockout.RemainingSeconds);
    }
}
