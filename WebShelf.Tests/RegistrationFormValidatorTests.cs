using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты валидатора полей формы заявки на регистрацию
/// (RegistrationFormValidator): форматы фамилии/имени/отчества, e-mail
/// и телефона +7 (XXX) XXX-XX-XX, тексты ошибок и маска телефона.
/// Тесты чистые — без БД и интерфейса.
/// </summary>
public class RegistrationFormValidatorTests
{
    // --- IsValidName: фамилия, имя, отчество ---

    [Theory]
    [InlineData("Иван", true)]
    [InlineData("Римский-Корсаков", true)]
    [InlineData("Жан-Люк", true)]
    [InlineData("О'Коннор", true)]
    [InlineData("Анна Мария", true)]
    [InlineData("Ёлкин", true)]
    [InlineData("Mary-Jane", true)]
    [InlineData("  Иван  ", true)]
    public void IsValidName_ValidNames_Accepted(string value, bool expected)
    {
        Assert.Equal(expected, RegistrationFormValidator.IsValidName(value));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Иван1")]
    [InlineData("123")]
    [InlineData("-Иван")]
    [InlineData("'Иван")]
    public void IsValidName_InvalidNames_Rejected(string value)
    {
        Assert.False(RegistrationFormValidator.IsValidName(value));
    }

    [Fact]
    public void IsValidName_LengthBoundary_MaxNameLengthAccepted()
    {
        string maxLengthName = new('а', RegistrationFormValidator.MaxNameLength);
        string tooLongName = new('а', RegistrationFormValidator.MaxNameLength + 1);

        Assert.True(RegistrationFormValidator.IsValidName(maxLengthName));
        Assert.False(RegistrationFormValidator.IsValidName(tooLongName));
    }

    // --- IsValidEmail ---

    [Theory]
    [InlineData("user@mail.ru", true)]
    [InlineData("user.name@sub.domain.org", true)]
    [InlineData("a@b.cc", true)]
    [InlineData("a+b@c.ru", true)]
    [InlineData("user_1@mail-server.ru", true)]
    [InlineData("  user@mail.ru  ", true)]
    public void IsValidEmail_ValidAddresses_Accepted(string value, bool expected)
    {
        Assert.Equal(expected, RegistrationFormValidator.IsValidEmail(value));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("user")]
    [InlineData("user@")]
    [InlineData("@mail.ru")]
    [InlineData("user@mail")]
    [InlineData("user@mail.")]
    [InlineData("user@@mail.ru")]
    [InlineData("user name@mail.ru")]
    [InlineData("user@mail..ru")]
    [InlineData("иван@почта.рф")]
    public void IsValidEmail_InvalidAddresses_Rejected(string value)
    {
        Assert.False(RegistrationFormValidator.IsValidEmail(value));
    }

    [Fact]
    public void IsValidEmail_LengthBoundary_MaxEmailLengthAccepted()
    {
        string maxLengthEmail = new string('a', RegistrationFormValidator.MaxEmailLength - 5) + "@b.cc";
        string tooLongEmail = new string('a', RegistrationFormValidator.MaxEmailLength - 4) + "@b.cc";

        Assert.Equal(RegistrationFormValidator.MaxEmailLength, maxLengthEmail.Length);
        Assert.True(RegistrationFormValidator.IsValidEmail(maxLengthEmail));
        Assert.False(RegistrationFormValidator.IsValidEmail(tooLongEmail));
    }

    // --- IsValidPhone: точный формат +7 (XXX) XXX-XX-XX ---

    [Theory]
    [InlineData("+7 (999) 123-45-67", true)]
    [InlineData("+7 (495) 000-00-00", true)]
    [InlineData("  +7 (999) 123-45-67  ", true)]
    public void IsValidPhone_ValidNumbers_Accepted(string value, bool expected)
    {
        Assert.Equal(expected, RegistrationFormValidator.IsValidPhone(value));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("89991234567")]
    [InlineData("+79991234567")]
    [InlineData("+7 999 123 45 67")]
    [InlineData("+7 (999) 123-45-6")]
    [InlineData("+7 (999) 123-45-678")]
    [InlineData("+7 (999)123-45-67")]
    [InlineData("8 (999) 123-45-67")]
    [InlineData("abc")]
    public void IsValidPhone_InvalidNumbers_Rejected(string value)
    {
        Assert.False(RegistrationFormValidator.IsValidPhone(value));
    }

    // --- IsApplicationValid: готовность всей формы (кнопка «Подать заявку») ---

    /// <summary>
    /// Валидные данные всех полей, даны оба согласия (персональные данные
    /// и cookie) — форма готова: кнопка «Подать заявку» активна.
    /// </summary>
    [Fact]
    public void IsApplicationValid_AllFieldsValidAndBothConsents_True()
    {
        bool valid = RegistrationFormValidator.IsApplicationValid(
            "Иванов", "Иван", "Иванович", "user@mail.ru", "+7 (999) 123-45-67", true, true);

        Assert.True(valid);
    }

    /// <summary>
    /// Все поля валидны, но согласие на обработку персональных данных
    /// не дано (снята галочка чек-бокса) — форма не готова: кнопка
    /// деактивируется.
    /// </summary>
    [Fact]
    public void IsApplicationValid_ConsentNotGiven_False()
    {
        bool valid = RegistrationFormValidator.IsApplicationValid(
            "Иванов", "Иван", "Иванович", "user@mail.ru", "+7 (999) 123-45-67", false, true);

        Assert.False(valid);
    }

    /// <summary>
    /// Все поля валидны, но согласие на обработку файлов cookie не дано —
    /// форма не готова: правила обработки аналогичны согласию на обработку
    /// персональных данных, снятая галочка блокирует кнопку.
    /// </summary>
    [Fact]
    public void IsApplicationValid_CookieConsentNotGiven_False()
    {
        bool valid = RegistrationFormValidator.IsApplicationValid(
            "Иванов", "Иван", "Иванович", "user@mail.ru", "+7 (999) 123-45-67", true, false);

        Assert.False(valid);
    }

    /// <summary>
    /// Пустая форма (исходное состояние) — не готова: кнопка «Подать заявку»
    /// по умолчанию неактивна.
    /// </summary>
    [Fact]
    public void IsApplicationValid_EmptyForm_False()
    {
        bool valid = RegistrationFormValidator.IsApplicationValid(
            string.Empty, string.Empty, string.Empty, string.Empty, string.Empty, false, false);

        Assert.False(valid);
    }

    /// <summary>
    /// Удаление данных любого одного поля делает форму некорректной —
    /// кнопка деактивируется (каждая позиция по очереди заменяется пустой).
    /// </summary>
    [Theory]
    [InlineData("", "Иван", "Иванович", "user@mail.ru", "+7 (999) 123-45-67", true, true)]
    [InlineData("Иванов", "", "Иванович", "user@mail.ru", "+7 (999) 123-45-67", true, true)]
    [InlineData("Иванов", "Иван", "", "user@mail.ru", "+7 (999) 123-45-67", true, true)]
    [InlineData("Иванов", "Иван", "Иванович", "", "+7 (999) 123-45-67", true, true)]
    [InlineData("Иванов", "Иван", "Иванович", "user@mail.ru", "", true, true)]
    public void IsApplicationValid_AnyFieldCleared_False(
        string lastName, string firstName, string patronymic, string email, string phone, bool consent, bool cookieConsent)
    {
        bool valid = RegistrationFormValidator.IsApplicationValid(
            lastName, firstName, patronymic, email, phone, consent, cookieConsent);

        Assert.False(valid);
    }

    /// <summary>
    /// Приведение любого поля к неправильному формату (цифры в ФИО, битый
    /// e-mail, неполный телефон) деактивирует кнопку на ранее заполненной
    /// валидной форме.
    /// </summary>
    [Theory]
    [InlineData("Иванов1", "Иван", "Иванович", "user@mail.ru", "+7 (999) 123-45-67", true, true)]
    [InlineData("Иванов", "Иван1", "Иванович", "user@mail.ru", "+7 (999) 123-45-67", true, true)]
    [InlineData("Иванов", "Иван", "Иванович1", "user@mail.ru", "+7 (999) 123-45-67", true, true)]
    [InlineData("Иванов", "Иван", "Иванович", "user@mail", "+7 (999) 123-45-67", true, true)]
    [InlineData("Иванов", "Иван", "Иванович", "user@mail.ru", "+7 (999) 123-45-6", true, true)]
    public void IsApplicationValid_AnyFieldInvalidFormat_False(
        string lastName, string firstName, string patronymic, string email, string phone, bool consent, bool cookieConsent)
    {
        bool valid = RegistrationFormValidator.IsApplicationValid(
            lastName, firstName, patronymic, email, phone, consent, cookieConsent);

        Assert.False(valid);
    }

    /// <summary>
    /// Пробелы по краям не портят валидность: значения полей нормализуются
    /// обрезкой, как при последующей отправке.
    /// </summary>
    [Fact]
    public void IsApplicationValid_TrailingSpacesInFields_True()
    {
        bool valid = RegistrationFormValidator.IsApplicationValid(
            " Иванов ", " Иван ", " Иванович ", " user@mail.ru ", " +7 (999) 123-45-67 ", true, true);

        Assert.True(valid);
    }

    // --- Тексты ошибок ---

    [Theory]
    [InlineData("", "фамилию", "Укажите фамилию.")]
    [InlineData("   ", "имя", "Укажите имя.")]
    [InlineData("Иван1", "отчество", "Допустимы только буквы, а также пробелы, дефисы и апострофы.")]
    public void NameError_InvalidValue_ReturnsMessage(string value, string fieldLabel, string expected)
    {
        Assert.Equal(expected, RegistrationFormValidator.NameError(value, fieldLabel));
    }

    [Fact]
    public void NameError_TooLongValue_ReturnsLengthMessage()
    {
        string tooLongName = new('а', RegistrationFormValidator.MaxNameLength + 1);

        Assert.Equal($"Максимальная длина — {RegistrationFormValidator.MaxNameLength} символов.",
            RegistrationFormValidator.NameError(tooLongName, "фамилию"));
    }

    [Fact]
    public void NameError_ValidValue_ReturnsNull()
    {
        Assert.Null(RegistrationFormValidator.NameError("Иванов", "фамилию"));
    }

    [Theory]
    [InlineData("", "Укажите адрес электронной почты.")]
    [InlineData("user", "Некорректный адрес электронной почты.")]
    [InlineData("user@mail", "Некорректный адрес электронной почты.")]
    public void EmailError_InvalidValue_ReturnsMessage(string value, string expected)
    {
        Assert.Equal(expected, RegistrationFormValidator.EmailError(value));
    }

    [Fact]
    public void EmailError_TooLongValue_ReturnsLengthMessage()
    {
        string tooLongEmail = new string('a', RegistrationFormValidator.MaxEmailLength) + "@b.cc";

        Assert.Equal($"Максимальная длина адреса — {RegistrationFormValidator.MaxEmailLength} символов.",
            RegistrationFormValidator.EmailError(tooLongEmail));
    }

    [Fact]
    public void EmailError_ValidValue_ReturnsNull()
    {
        Assert.Null(RegistrationFormValidator.EmailError("user@mail.ru"));
    }

    [Theory]
    [InlineData("", "Укажите номер телефона.")]
    [InlineData("+7 999", "Номер телефона должен быть в формате +7 (XXX) XXX-XX-XX.")]
    [InlineData("89991234567", "Номер телефона должен быть в формате +7 (XXX) XXX-XX-XX.")]
    public void PhoneError_InvalidValue_ReturnsMessage(string value, string expected)
    {
        Assert.Equal(expected, RegistrationFormValidator.PhoneError(value));
    }

    [Fact]
    public void PhoneError_ValidValue_ReturnsNull()
    {
        Assert.Null(RegistrationFormValidator.PhoneError("+7 (999) 123-45-67"));
    }

    [Fact]
    public void ConsentError_NotConsented_ReturnsMessage()
    {
        Assert.Equal("Необходимо согласие на обработку персональных данных.",
            RegistrationFormValidator.ConsentError(false));
    }

    [Fact]
    public void ConsentError_Consented_ReturnsNull()
    {
        Assert.Null(RegistrationFormValidator.ConsentError(true));
    }

    [Fact]
    public void CookieConsentError_NotConsented_ReturnsMessage()
    {
        Assert.Equal("Необходимо согласие на обработку файлов cookie.",
            RegistrationFormValidator.CookieConsentError(false));
    }

    [Fact]
    public void CookieConsentError_Consented_ReturnsNull()
    {
        Assert.Null(RegistrationFormValidator.CookieConsentError(true));
    }

    [Fact]
    public void DuplicateMessages_NonEmpty()
    {
        // Тексты предупреждений о занятых контактах показываются под полями
        // e-mail и телефона — пустая строка означала бы «молчаливую» блокировку
        Assert.False(string.IsNullOrWhiteSpace(RegistrationFormValidator.DuplicateEmailMessage));
        Assert.False(string.IsNullOrWhiteSpace(RegistrationFormValidator.DuplicatePhoneMessage));
    }

    // --- ApplyPhoneMask: маска +7 (XXX) XXX-XX-XX по мере ввода ---

    [Theory]
    [InlineData("", "")]
    [InlineData("9", "+7 (9")]
    [InlineData("99", "+7 (99")]
    [InlineData("999", "+7 (999")]
    [InlineData("9999", "+7 (999) 9")]
    [InlineData("99999", "+7 (999) 99")]
    [InlineData("999999", "+7 (999) 999")]
    [InlineData("9999999", "+7 (999) 999-9")]
    [InlineData("99999999", "+7 (999) 999-99")]
    [InlineData("999999999", "+7 (999) 999-99-9")]
    [InlineData("9991234567", "+7 (999) 123-45-67")]
    [InlineData("7", "+7 (")]
    [InlineData("8", "+7 (")]
    [InlineData("78", "+7 (8")]
    [InlineData("79991234567", "+7 (999) 123-45-67")]
    [InlineData("89991234567", "+7 (999) 123-45-67")]
    [InlineData("+7 (999) 123-45-67", "+7 (999) 123-45-67")]
    [InlineData("+7 (999) 123-45-678", "+7 (999) 123-45-67")]
    [InlineData("99991234567", "+7 (999) 912-34-56")]
    [InlineData("abc", "")]
    [InlineData("+7abc999def123-45-67", "+7 (999) 123-45-67")]
    public void ApplyPhoneMask_VariousInputs_Masked(string input, string expected)
    {
        Assert.Equal(expected, RegistrationFormValidator.ApplyPhoneMask(input));
    }

    [Fact]
    public void ApplyPhoneMask_AlreadyMaskedValue_Idempotent()
    {
        const string masked = "+7 (999) 123-45-67";

        Assert.Equal(masked, RegistrationFormValidator.ApplyPhoneMask(masked));
    }
}
