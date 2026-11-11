namespace WebShelf.Classes.Service;

/// <summary>
/// Сервис заявок на регистрацию для окна «Подача заявки на регистрацию»
/// (страница /entry, компонент RegistrationApplicationForm): проверка
/// уникальности контактных данных и запись заявки в таблицу
/// <c>webshelf.registration_requests</c>.
/// Реализация — <see cref="RegistrationRequestService"/> (singleton из
/// Program.Main); форма заявки зависит только от интерфейса, тесты подменяют
/// его фейком (по образцу <see cref="IPolicyContentSource"/>).
/// </summary>
internal interface IRegistrationRequestService
{
    /// <summary>
    /// Проверяет уникальность контактных данных: есть ли в таблице заявок
    /// уже поданная заявка с таким адресом электронной почты и/или таким
    /// номером телефона. Пустая строка вместо проверяемого значения означает
    /// «это контакт не проверять» (соответствующий флаг результата будет
    /// <see langword="false"/>). E-mail сравнивается без учёта регистра
    /// (хранится в нижнем регистре), телефон — точным совпадением
    /// (формат маски формы каноничен).
    /// </summary>
    /// <param name="email">Проверяемый адрес электронной почты
    /// или пустая строка.</param>
    /// <param name="phone">Проверяемый номер телефона
    /// или пустая строка.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Результат проверки: какие контакты уже заняты поданной
    /// заявкой; никогда <see langword="null"/>.</returns>
    Task<RegistrationContactCheckResult> CheckContactsAsync(
        string email,
        string phone,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Записывает заявку в таблицу <c>webshelf.registration_requests</c>
    /// в одной транзакции: пермит повторно проверяется и блокируется
    /// (<c>SELECT … FOR UPDATE</c>), заявка вставляется (идентификатор УЗ AD —
    /// NULL, заявка ожидает решения администратора), и только после успешной
    /// вставки счётчик пермита уменьшается на 1. Вместе с заявкой фиксируются
    /// номера действующих редакций политик (персональные данные, cookie) и
    /// время подачи по UTC с точностью до секунды. Уникальность e-mail и
    /// телефона гарантируется ограничениями таблицы (страховка от гонки
    /// между предварительной проверкой и вставкой).
    /// </summary>
    /// <param name="application">Данные заявки из формы.</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Результат подачи; никогда <see langword="null"/>. Значение
    /// пермита в логи не попадает (правило маскировки).</returns>
    Task<RegistrationSubmitResult> SubmitAsync(
        RegistrationApplication application,
        CancellationToken cancellationToken = default);
}
