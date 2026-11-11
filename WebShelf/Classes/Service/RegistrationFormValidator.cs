using System.Text;
using System.Text.RegularExpressions;

namespace WebShelf.Classes.Service;

/// <summary>
/// Валидация полей формы заявки на регистрацию: фамилия, имя, отчество,
/// адрес электронной почты, номер телефона в формате
/// «+7 (XXX) XXX-XX-XX», согласия на обработку персональных данных
/// и файлов cookie. Проверки форматов чистые (без обращения к серверу
/// и БД) и выполняются по мере ввода — компонент формы вызывает их после
/// каждого изменения поля. Методы <c>*Error</c> возвращают текст ошибки
/// для интерфейса или <see langword="null"/>, если поле корректно.
/// Сообщения о занятых контактах (дубликат заявки) — константы: результат
/// проверки уникальности в БД приходит асинхронно, тексты ошибок полей
/// остаются в одном месте.
/// </summary>
internal static partial class RegistrationFormValidator
{
    /// <summary>Подсказка формата телефона (плейсхолдер поля и текст ошибки).</summary>
    internal const string PhoneMaskHint = "+7 (XXX) XXX-XX-XX";

    /// <summary>Максимальная длина фамилии, имени и отчества, символов.</summary>
    internal const int MaxNameLength = 100;

    /// <summary>
    /// Максимальная длина адреса электронной почты, символов — предел RFC 5321,
    /// совпадает с колонкой <c>email</c> таблицы <c>webshelf.registration_requests</c>.
    /// </summary>
    internal const int MaxEmailLength = 254;

    /// <summary>Сообщение о занятом адресе электронной почты (дубликат заявки).</summary>
    internal const string DuplicateEmailMessage = "Заявка с таким адресом электронной почты уже подана.";

    /// <summary>Сообщение о занятом номере телефона (дубликат заявки).</summary>
    internal const string DuplicatePhoneMessage = "Заявка с таким номером телефона уже подана.";

    /// <summary>
    /// Формат телефона: «+7 (XXX) XXX-XX-XX» — 10 значащих цифр после кода страны.
    /// </summary>
    [GeneratedRegex(@"^\+7 \(\d{3}\) \d{3}-\d{2}-\d{2}$")]
    private static partial Regex PhoneRegex();

    /// <summary>
    /// Адрес электронной почты: локальная часть, «@», домен из меток через точку
    /// с доменом верхнего уровня не короче двух букв. Проверка формата
    /// (не фактического существования адреса).
    /// </summary>
    [GeneratedRegex(@"^[A-Za-z0-9._%+-]+@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}$")]
    private static partial Regex EmailRegex();

    /// <summary>
    /// Фамилия, имя, отчество: буквы (в том числе кириллица), пробелы, дефисы
    /// и апострофы (двойные фамилии, иностранные имена); первый символ — буква.
    /// </summary>
    [GeneratedRegex(@"^[\p{L}][\p{L}\s'-]*$")]
    private static partial Regex NameRegex();

    /// <summary>
    /// Проверяет корректность фамилии, имени или отчества.
    /// </summary>
    /// <param name="value">Введённое значение.</param>
    /// <returns><see langword="true"/> — значение корректно.</returns>
    internal static bool IsValidName(string value)
    {
        string trimmed = value.Trim();
        return trimmed.Length is > 0 and <= MaxNameLength && NameRegex().IsMatch(trimmed);
    }

    /// <summary>
    /// Проверяет корректность адреса электронной почты.
    /// </summary>
    /// <param name="value">Введённое значение.</param>
    /// <returns><see langword="true"/> — значение корректно.</returns>
    internal static bool IsValidEmail(string value)
    {
        string trimmed = value.Trim();
        return trimmed.Length is > 0 and <= MaxEmailLength && EmailRegex().IsMatch(trimmed);
    }

    /// <summary>
    /// Проверяет корректность номера телефона: точное соответствие формату
    /// «+7 (XXX) XXX-XX-XX».
    /// </summary>
    /// <param name="value">Введённое значение.</param>
    /// <returns><see langword="true"/> — значение корректно.</returns>
    internal static bool IsValidPhone(string value)
    {
        string trimmed = value.Trim();
        return trimmed.Length > 0 && PhoneRegex().IsMatch(trimmed);
    }

    /// <summary>
    /// Проверяет готовность всей формы заявки к отправке: все поля обязательны
    /// и должны быть корректны (фамилия, имя, отчество, e-mail, телефон
    /// в формате +7 (XXX) XXX-XX-XX), согласия на обработку персональных
    /// данных и файлов cookie должны быть даны. Кнопка «Подать заявку»
    /// активна только в этом состоянии (дополнительно форма требует
    /// подтверждённой уникальности e-mail и телефона): проверка
    /// перевычисляется при каждом вводе, поэтому любое исправление, делающее
    /// форму некорректной (удаление данных, неверный формат, снятие
    /// согласия), снова блокирует кнопку.
    /// </summary>
    /// <param name="lastName">Фамилия.</param>
    /// <param name="firstName">Имя.</param>
    /// <param name="patronymic">Отчество.</param>
    /// <param name="email">Адрес электронной почты.</param>
    /// <param name="phone">Номер телефона в формате +7 (XXX) XXX-XX-XX.</param>
    /// <param name="consent"><see langword="true"/> — согласие на обработку
    /// персональных данных дано.</param>
    /// <param name="cookieConsent"><see langword="true"/> — согласие
    /// на обработку файлов cookie дано.</param>
    /// <returns><see langword="true"/> — форма заполнена корректно целиком.</returns>
    internal static bool IsApplicationValid(
        string lastName,
        string firstName,
        string patronymic,
        string email,
        string phone,
        bool consent,
        bool cookieConsent)
        => IsValidName(lastName)
           && IsValidName(firstName)
           && IsValidName(patronymic)
           && IsValidEmail(email)
           && IsValidPhone(phone)
           && consent
           && cookieConsent;

    /// <summary>
    /// Ошибка поля «Фамилия»/«Имя»/«Отчество».
    /// </summary>
    /// <param name="value">Введённое значение.</param>
    /// <param name="fieldLabel">Название поля в винительном падеже
    /// («фамилию», «имя», «отчество») для сообщения о незаполненном поле.</param>
    /// <returns>Текст ошибки или <see langword="null"/>, если поле корректно.</returns>
    internal static string? NameError(string value, string fieldLabel)
    {
        string trimmed = value.Trim();

        if (trimmed.Length == 0)
        {
            return $"Укажите {fieldLabel}.";
        }

        if (trimmed.Length > MaxNameLength)
        {
            return $"Максимальная длина — {MaxNameLength} символов.";
        }

        return NameRegex().IsMatch(trimmed)
            ? null
            : "Допустимы только буквы, а также пробелы, дефисы и апострофы.";
    }

    /// <summary>
    /// Ошибка поля «E-Mail».
    /// </summary>
    /// <param name="value">Введённое значение.</param>
    /// <returns>Текст ошибки или <see langword="null"/>, если поле корректно.</returns>
    internal static string? EmailError(string value)
    {
        string trimmed = value.Trim();

        if (trimmed.Length == 0)
        {
            return "Укажите адрес электронной почты.";
        }

        if (trimmed.Length > MaxEmailLength)
        {
            return $"Максимальная длина адреса — {MaxEmailLength} символов.";
        }

        return EmailRegex().IsMatch(trimmed)
            ? null
            : "Некорректный адрес электронной почты.";
    }

    /// <summary>
    /// Ошибка поля «Номер телефона».
    /// </summary>
    /// <param name="value">Введённое значение.</param>
    /// <returns>Текст ошибки или <see langword="null"/>, если поле корректно.</returns>
    internal static string? PhoneError(string value)
    {
        string trimmed = value.Trim();

        if (trimmed.Length == 0)
        {
            return "Укажите номер телефона.";
        }

        return PhoneRegex().IsMatch(trimmed)
            ? null
            : $"Номер телефона должен быть в формате {PhoneMaskHint}.";
    }

    /// <summary>
    /// Ошибка чек-бокса согласия на обработку персональных данных.
    /// </summary>
    /// <param name="consented"><see langword="true"/> — согласие установлено.</param>
    /// <returns>Текст ошибки или <see langword="null"/>, если согласие дано.</returns>
    internal static string? ConsentError(bool consented)
        => consented ? null : "Необходимо согласие на обработку персональных данных.";

    /// <summary>
    /// Ошибка чек-бокса согласия на обработку файлов cookie.
    /// Правила обработки аналогичны согласию на обработку персональных
    /// данных: чек-бокс обязателен, снятая галочка блокирует подачу заявки.
    /// </summary>
    /// <param name="consented"><see langword="true"/> — согласие установлено.</param>
    /// <returns>Текст ошибки или <see langword="null"/>, если согласие дано.</returns>
    internal static string? CookieConsentError(bool consented)
        => consented ? null : "Необходимо согласие на обработку файлов cookie.";

    /// <summary>
    /// Укладывает введённые цифры телефона в маску «+7 (XXX) XXX-XX-XX»:
    /// вызывается после каждого нажатия клавиши в поле телефона. Посторонние
    /// символы отбрасываются; ведущая 7 или 8 считается кодом страны
    /// (единственная ведущая цифра превращается в префикс «+7 (»);
    /// значащих цифр после кода страны — не больше 10.
    /// </summary>
    /// <param name="input">Произвольный введённый текст.</param>
    /// <returns>Значение, приведённое к маске (частично заполненной); пустая
    /// строка, если цифр нет. Результат идемпотентен: повторное применение
    /// к уже замаскированному значению не меняет его.</returns>
    internal static string ApplyPhoneMask(string input)
    {
        StringBuilder digits = new();
        foreach (char symbol in input)
        {
            if (char.IsAsciiDigit(symbol))
            {
                digits.Append(symbol);
            }
        }

        string significant = digits.ToString();
        if (significant.Length == 0)
        {
            return string.Empty;
        }

        // Ведущая 7 или 8 — код страны +7: одиночная цифра открывает маску,
        // остальной ввод отбрасывает код страны (пользователь набрал номер целиком)
        if (significant[0] is '7' or '8')
        {
            if (significant.Length == 1)
            {
                return "+7 (";
            }

            significant = significant[1..];
        }

        if (significant.Length > 10)
        {
            significant = significant[..10];
        }

        string masked = "+7 (" + significant[..Math.Min(3, significant.Length)];

        if (significant.Length > 3)
        {
            masked += ") " + significant[3..Math.Min(6, significant.Length)];
        }

        if (significant.Length > 6)
        {
            masked += "-" + significant[6..Math.Min(8, significant.Length)];
        }

        if (significant.Length > 8)
        {
            masked += "-" + significant[8..Math.Min(10, significant.Length)];
        }

        return masked;
    }
}
