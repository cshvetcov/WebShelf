namespace WebShelf.Classes.Service;

/// <summary>
/// Данные заявки на регистрацию, передаваемые формой окна «Подача заявки
/// на регистрацию» сервису <see cref="RegistrationRequestService"/> для
/// записи в таблицу <c>webshelf.registration_requests</c>.
/// </summary>
/// <param name="LastName">Фамилия кандидата.</param>
/// <param name="FirstName">Имя кандидата.</param>
/// <param name="Patronymic">Отчество кандидата (обязательное поле формы).</param>
/// <param name="Email">Адрес электронной почты кандидата.</param>
/// <param name="Phone">Номер телефона кандидата в формате
/// «+7 (XXX) XXX-XX-XX».</param>
/// <param name="Permit">Значение пермита, по которому открыто окно заявки
/// (секретный код: не логируется ни при каких условиях).</param>
internal sealed record RegistrationApplication(
    string LastName,
    string FirstName,
    string Patronymic,
    string Email,
    string Phone,
    string Permit);
