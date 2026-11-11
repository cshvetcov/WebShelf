namespace WebShelf.Classes.Service;

/// <summary>
/// Результат подачи заявки на регистрацию: статус выполнения и идентификатор
/// записанной строки (только для <see cref="RegistrationSubmitStatus.Success"/>).
/// </summary>
/// <param name="Status">Статус подачи.</param>
/// <param name="RequestId">Служебный идентификатор записанной заявки
/// (первичный ключ <c>webshelf.registration_requests.id</c>); 0, если заявка
/// не записана.</param>
internal sealed record RegistrationSubmitResult(RegistrationSubmitStatus Status, long RequestId)
{
    /// <summary>
    /// <see langword="true"/> — заявка успешно записана в таблицу заявок.
    /// </summary>
    internal bool IsSuccess => Status == RegistrationSubmitStatus.Success;

    /// <summary>
    /// Строит успешный результат с идентификатором записанной заявки.
    /// </summary>
    /// <param name="requestId">Служебный идентификатор записанной заявки.</param>
    /// <returns>Результат подачи; никогда <see langword="null"/>.</returns>
    internal static RegistrationSubmitResult FromSuccess(long requestId)
        => new(RegistrationSubmitStatus.Success, requestId);

    /// <summary>
    /// Строит результат с нулевым идентификатором (заявка не записана).
    /// </summary>
    /// <param name="status">Статус подачи — любой, кроме Success.</param>
    /// <returns>Результат подачи; никогда <see langword="null"/>.</returns>
    internal static RegistrationSubmitResult FromStatus(RegistrationSubmitStatus status)
        => new(status, 0);
}
