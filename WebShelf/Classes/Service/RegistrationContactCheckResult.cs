namespace WebShelf.Classes.Service;

/// <summary>
/// Результат проверки уникальности контактных данных заявки в таблице
/// <c>webshelf.registration_requests</c> (см. <see cref="IRegistrationRequestService.CheckContactsAsync"/>).
/// </summary>
/// <param name="EmailTaken"><see langword="true"/> — заявка с таким адресом
/// электронной почты уже подана (проверяемое значение передавалось
/// непустым).</param>
/// <param name="PhoneTaken"><see langword="true"/> — заявка с таким номером
/// телефона уже подана (проверяемое значение передавалось непустым).</param>
/// <remarks>
/// Значение <see langword="false"/> для поля, чей проверяемый аргумент был
/// пустой строкой, означает лишь отсутствие совпадений с пустой строкой —
/// пустой контакт не проверялся (в таблице хранятся только непустые значения).
/// </remarks>
internal sealed record RegistrationContactCheckResult(bool EmailTaken, bool PhoneTaken)
{
    /// <summary>
    /// Результат «контакты свободны» — ни e-mail, ни телефон не найдены
    /// среди поданных заявок.
    /// </summary>
    internal static RegistrationContactCheckResult None { get; } = new(false, false);
}
