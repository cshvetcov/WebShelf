namespace WebShelf.Classes.Service;

/// <summary>
/// Результат проверки регистрационного пермита: статус и счётчик оставшихся
/// регистраций, полученный из таблицы <c>webshelf.registration_permits</c>.
/// </summary>
/// <param name="Status">Статус проверки.</param>
/// <param name="Counter">Счётчик оставшихся регистраций пермита
/// (0, если пермит не найден).</param>
internal sealed record RegistrationPermitCheckResult(RegistrationPermitStatus Status, int Counter)
{
    /// <summary>
    /// <see langword="true"/> — пермит пригоден для подачи заявки на регистрацию
    /// (найден в базе данных, счётчик оставшихся регистраций больше нуля).
    /// </summary>
    internal bool IsUsable => Status == RegistrationPermitStatus.Usable;

    /// <summary>
    /// Строит результат проверки по счётчику пермита, прочитанному из базы данных.
    /// </summary>
    /// <param name="counter">Счётчик оставшихся регистраций
    /// или <see langword="null"/>, если пермит не найден.</param>
    /// <returns>Результат проверки; никогда не <see langword="null"/>.</returns>
    internal static RegistrationPermitCheckResult FromCounter(int? counter)
        => counter switch
        {
            null => new RegistrationPermitCheckResult(RegistrationPermitStatus.NotFound, 0),
            > 0 => new RegistrationPermitCheckResult(RegistrationPermitStatus.Usable, counter.Value),
            _ => new RegistrationPermitCheckResult(RegistrationPermitStatus.Exhausted, counter.Value)
        };
}
