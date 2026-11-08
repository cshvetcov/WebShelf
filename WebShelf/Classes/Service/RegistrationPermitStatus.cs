namespace WebShelf.Classes.Service;

/// <summary>
/// Статус проверки регистрационного пермита в базе данных
/// (см. <see cref="RegistrationPermitChecker"/>).
/// </summary>
internal enum RegistrationPermitStatus
{
    /// <summary>
    /// Пермит найден в базе данных, счётчик оставшихся регистраций больше нуля —
    /// пермит пригоден для подачи заявки на регистрацию.
    /// </summary>
    Usable,

    /// <summary>
    /// Пермит не найден в базе данных (в том числе введено пустое значение).
    /// </summary>
    NotFound,

    /// <summary>
    /// Пермит найден, но счётчик оставшихся регистраций равен нулю —
    /// пермит исчерпан и регистрации не подлежит.
    /// </summary>
    Exhausted
}
