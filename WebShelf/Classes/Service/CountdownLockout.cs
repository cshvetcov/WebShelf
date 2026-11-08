namespace WebShelf.Classes.Service;

/// <summary>
/// Логика обратного отсчёта блокировки: запускается на заданное число секунд
/// и уменьшает остаток на единицу за каждый тик. Владелец класса отвечает
/// за вызов тиков (например, по таймеру раз в секунду) и за синхронизацию
/// с контуром Blazor (InvokeAsync); сам класс потокобезопасность не обеспечивает —
/// все обращения выполняются в контуре владельца.
/// </summary>
/// <remarks>
/// Используется на странице <c>/entry</c> для блокировки кнопки
/// «Зарегистрироваться» после неудачной проверки пермита (15 секунд
/// с обратным отсчётом). Блокировка формы входа после неудачных попыток
/// входа (LoginGuard) устроена иначе и этим классом не заменяется.
/// </remarks>
internal sealed class CountdownLockout
{
    /// <summary>
    /// <see langword="true"/> — блокировка активна (остаток времени больше нуля).
    /// </summary>
    internal bool IsLocked => RemainingSeconds > 0;

    /// <summary>
    /// Оставшееся число секунд блокировки; 0 — блокировка не активна.
    /// </summary>
    internal int RemainingSeconds { get; private set; }

    /// <summary>
    /// Запускает (или перезапускает) отсчёт на заданное число секунд.
    /// Неположительное значение сразу оставляет блокировку снятой.
    /// </summary>
    /// <param name="seconds">Число секунд блокировки.</param>
    internal void Start(int seconds)
    {
        RemainingSeconds = seconds > 0 ? seconds : 0;
    }

    /// <summary>
    /// Один тик отсчёта: уменьшает остаток на одну секунду, но не ниже нуля.
    /// </summary>
    internal void Tick()
    {
        if (RemainingSeconds > 0)
        {
            RemainingSeconds--;
        }
    }
}
