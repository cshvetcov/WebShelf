using WebShelf.Classes.DC;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты класса Domain: нормализация имён пользователей к формату username@domain,
/// построение LDAP-пути, валидация аргументов конструктора, а также формирование
/// списка необходимых групп безопасности из шаблонов имён (подстановка заполнителя
/// {InstanceIdShort}, отбраковка шаблонов с опечаткой).
/// </summary>
public class DomainTests
{
    #region NormalizeUserName

    /// <summary>
    /// Имя без разделителей дополняется доменом.
    /// </summary>
    [Theory]
    [InlineData("ivanov", "company.local", "ivanov@company.local")]
    [InlineData("IVANOV", "company.local", "IVANOV@company.local")]
    [InlineData(" ivanov ", "company.local", "ivanov@company.local")]
    [InlineData("ivanov", " company.local ", "ivanov@company.local")]
    [InlineData("o'connor", "company.local", "o'connor@company.local")]
    public void NormalizeUserName_BareName_AppendsDomain(string userName, string domainName, string expected)
    {
        string? result = Domain.NormalizeUserName(userName, domainName);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Формат DOMAIN\user приводится к username@domain.
    /// </summary>
    [Theory]
    [InlineData("DOMAIN\\ivanov", "company.local", "ivanov@company.local")]
    [InlineData("COMPANY\\ivanov", "company.local", "ivanov@company.local")]
    [InlineData("DOMAIN\\ ivanov", "company.local", "ivanov@company.local")]
    [InlineData(" ivanov\\ ", "company.local", null)]
    public void NormalizeUserName_DownLevelLogon_ConvertsToUpn(string userName, string domainName, string? expected)
    {
        string? result = Domain.NormalizeUserName(userName, domainName);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Корректный UPN для целевого домена возвращается без изменений
    /// (регистр доменной части не важен).
    /// </summary>
    [Theory]
    [InlineData("ivanov@company.local", "company.local", "ivanov@company.local")]
    [InlineData("ivanov@COMPANY.LOCAL", "company.local", "ivanov@COMPANY.LOCAL")]
    [InlineData(" ivanov@company.local ", "company.local", "ivanov@company.local")]
    public void NormalizeUserName_ValidUpn_ReturnedUnchanged(string userName, string domainName, string expected)
    {
        string? result = Domain.NormalizeUserName(userName, domainName);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Некорректные имена пользователей отклоняются (возвращается null).
    /// </summary>
    [Theory]
    [InlineData(null, "company.local")]                  // имя не задано
    [InlineData("", "company.local")]                    // пустое имя
    [InlineData("   ", "company.local")]                 // имя из пробелов
    [InlineData("ivanov", null)]                         // домен не задан
    [InlineData("ivanov", "")]                           // пустой домен
    [InlineData("ivanov", "   ")]                        // домен из пробелов
    [InlineData("@company.local", "company.local")]      // пустая часть имени
    [InlineData("user@", "company.local")]               // пустая доменная часть
    [InlineData("a@b@company.local", "company.local")]   // два разделителя @
    [InlineData("user@other.local", "company.local")]    // чужой домен
    [InlineData("\\ivanov", "company.local")]            // слэш в начале
    [InlineData("ivanov\\", "company.local")]            // слэш в конце
    public void NormalizeUserName_InvalidInput_ReturnsNull(string? userName, string? domainName)
    {
        string? result = Domain.NormalizeUserName(userName!, domainName!);

        Assert.Null(result);
    }

    /// <summary>
    /// UPN, введённый в другом регистре, но совпадающий с доменом без учёта регистра,
    /// принимается (сравнение доменной части нечувствительно к регистру).
    /// </summary>
    [Fact]
    public void NormalizeUserName_UpnCaseInsensitiveDomain_Accepted()
    {
        string? result = Domain.NormalizeUserName("Ivanov@Company.Local", "COMPANY.LOCAL");

        Assert.Equal("Ivanov@Company.Local", result);
    }

    #endregion

    #region Валидация аргументов конструктора

    /// <summary>
    /// Конструктор отклоняет пустое имя домена (проверка до обращения к мастер-ключу).
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_EmptyDomain_ThrowsArgumentException(string? domain)
    {
        Assert.Throws<ArgumentException>(() =>
            new Domain(domain!, "abcdef012345", "encryptedUser", "encryptedPassword"));
    }

    /// <summary>
    /// Конструктор отклоняет пустой короткий префикс InstanceId.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_EmptyInstanceIdShort_ThrowsArgumentException(string? instanceIdShort)
    {
        Assert.Throws<ArgumentException>(() =>
            new Domain("company.local", instanceIdShort!, "encryptedUser", "encryptedPassword"));
    }

    /// <summary>
    /// Конструктор отклоняет пустые зашифрованные учётные данные.
    /// </summary>
    [Theory]
    [InlineData(null, "encryptedPassword")]
    [InlineData("", "encryptedPassword")]
    [InlineData("   ", "encryptedPassword")]
    [InlineData("encryptedUser", null)]
    [InlineData("encryptedUser", "")]
    [InlineData("encryptedUser", "   ")]
    public void Constructor_EmptyEncryptedCredentials_ThrowsArgumentException(
        string? encryptedUser, string? encryptedPassword)
    {
        Assert.Throws<ArgumentException>(() =>
            new Domain("company.local", "abcdef012345", encryptedUser!, encryptedPassword!));
    }

    #endregion

    #region Полный конструктор (только Windows: реестр + DPAPI)

    /// <summary>
    /// Полный конструктор расшифровывает учётные данные, нормализует логин
    /// и строит LDAP-путь корня домена. Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void Constructor_OnWindows_ValidCredentials_BuildsDomain()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!; // SkipUnless гарантирует ненулевое значение при продолжении

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("company.local", "abcdef012345", encryptedUser, encryptedPassword);

        Assert.Equal("company.local", domain.Name);
        Assert.Equal("LDAP://company.local/DC=company,DC=local", domain.Path);
        // Логин нормализуется к формату username@domain
        Assert.Equal("svc_webshelf@company.local", domain.GetDecryptedUser());
    }

    /// <summary>
    /// Конструктор отклоняет учётные данные, не поддающиеся расшифровке.
    /// Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void Constructor_OnWindows_InvalidEncryptedData_ThrowsInvalidOperationException()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");

        // Корректная Base64, но данные не зашифрованы сервисом — MAC не сойдётся
        string garbageUser = Convert.ToBase64String(new byte[65]);

        Assert.Throws<InvalidOperationException>(() =>
            new Domain("company.local", "abcdef012345", garbageUser, garbageUser));
    }

    #endregion

    #region EnsureRequiredGroupsExist

    /// <summary>
    /// EnsureRequiredGroupsExist при пустом списке групп возвращает true
    /// без обращения к AD (учётные данные даже не расшифровываются).
    /// Список групп в настоящее время пуст — это корректное состояние.
    /// Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void EnsureRequiredGroupsExist_OnWindows_EmptyList_ReturnsTrue()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!; // SkipUnless гарантирует ненулевое значение при продолжении

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("company.local", "abcdef012345", encryptedUser, encryptedPassword);

        // Пустой список: метод завершается успешно до любых сетевых операций
        Assert.True(domain.EnsureRequiredGroupsExist());
    }

    #endregion

    #region ExpandGroupTemplate

    /// <summary>
    /// Заполнитель {InstanceIdShort} заменяется коротким префиксом InstanceId
    /// во всех вхождениях; регистр заполнителя не важен, пробелы по краям шаблона
    /// обрезаются, шаблон без заполнителя возвращается без изменений.
    /// </summary>
    [Theory]
    [InlineData("WebShelf-{InstanceIdShort}-Administrator", "000000000000", "WebShelf-000000000000-Administrator")]
    [InlineData("WebShelf-{InstanceIdShort}-Users", "abcdef012345", "WebShelf-abcdef012345-Users")]
    [InlineData("WebShelf-{instanceidshort}-Users", "abcdef012345", "WebShelf-abcdef012345-Users")]
    [InlineData(" WebShelf-{InstanceIdShort}-Users ", "abcdef012345", "WebShelf-abcdef012345-Users")]
    [InlineData("WebShelf-{InstanceIdShort}-{InstanceIdShort}-X", "ab12", "WebShelf-ab12-ab12-X")]
    [InlineData("{InstanceIdShort}", "abcdef012345", "abcdef012345")]
    [InlineData("WebShelf-Fixed-Group", "abcdef012345", "WebShelf-Fixed-Group")]
    public void ExpandGroupTemplate_ValidTemplate_SubstitutesInstanceIdShort(
        string template, string instanceIdShort, string expected)
    {
        string result = Domain.ExpandGroupTemplate(template, instanceIdShort);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Метод выполняет только подстановку и не отклоняет шаблон с опечаткой:
    /// некорректный заполнитель (опечатка, незакрытая или лишняя фигурная скобка)
    /// проходит в результат без изменений, корректные вхождения при этом заменяются.
    /// Отбраковка таких шаблонов выполняется в FillRequiredGroupsFromTemplates.
    /// </summary>
    [Theory]
    [InlineData("WebShelf-{InstanseIdShort}-Administrator", "abcdef012345", "WebShelf-{InstanseIdShort}-Administrator")]
    [InlineData("WebShelf-{InstanceIdShort-Manager", "abcdef012345", "WebShelf-{InstanceIdShort-Manager")]
    [InlineData("WebShelf-Users}", "abcdef012345", "WebShelf-Users}")]
    [InlineData("WebShelf-{InstanceIdShort}-{Role}", "abcdef012345", "WebShelf-abcdef012345-{Role}")]
    public void ExpandGroupTemplate_InvalidPlaceholder_NotRejected(
        string template, string instanceIdShort, string expected)
    {
        string result = Domain.ExpandGroupTemplate(template, instanceIdShort);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Пустой шаблон имени группы отклоняется.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ExpandGroupTemplate_EmptyTemplate_ThrowsArgumentException(string? template)
    {
        Assert.Throws<ArgumentException>(() =>
            Domain.ExpandGroupTemplate(template!, "abcdef012345"));
    }

    /// <summary>
    /// Пустой короткий префикс InstanceId отклоняется.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ExpandGroupTemplate_EmptyInstanceIdShort_ThrowsArgumentException(string? instanceIdShort)
    {
        Assert.Throws<ArgumentException>(() =>
            Domain.ExpandGroupTemplate("WebShelf-{InstanceIdShort}-Users", instanceIdShort!));
    }

    #endregion

    #region FillRequiredGroupsFromTemplates

    /// <summary>
    /// Список групп формируется из шаблонов: заполнитель заменяется коротким
    /// префиксом InstanceId, пробелы обрезаются, регистр заполнителя не важен.
    /// Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_OnWindows_SubstitutesInstanceIdShort()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!; // SkipUnless гарантирует ненулевое значение при продолжении

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("company.local", "abcdef012345", encryptedUser, encryptedPassword);

        string[] templates =
        [
            "WebShelf-{InstanceIdShort}-Users",
            " WebShelf-{InstanceIdShort}-Administrator ",
            "WebShelf-{INSTANCEIDSHORT}-Guest"
        ];

        Assert.True(domain.FillRequiredGroupsFromTemplates(templates));
        Assert.Equal(3, domain.RequiredGroups.Count);
        Assert.Contains("WebShelf-abcdef012345-Users", domain.RequiredGroups);
        Assert.Contains("WebShelf-abcdef012345-Administrator", domain.RequiredGroups);
        Assert.Contains("WebShelf-abcdef012345-Guest", domain.RequiredGroups);
    }

    /// <summary>
    /// Дубликаты шаблонов (без учёта регистра) дают одну группу в списке.
    /// Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_OnWindows_DuplicateTemplates_Deduplicated()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!;

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("company.local", "abcdef012345", encryptedUser, encryptedPassword);

        string[] templates = ["WebShelf-{InstanceIdShort}-Users", "webshelf-{InstanceIdShort}-users"];

        Assert.True(domain.FillRequiredGroupsFromTemplates(templates));
        Assert.Single(domain.RequiredGroups);
    }

    /// <summary>
    /// Пустой список шаблонов — корректное состояние: список групп остаётся пустым.
    /// Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_OnWindows_EmptyTemplates_ListStaysEmpty()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!;

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("company.local", "abcdef012345", encryptedUser, encryptedPassword);

        Assert.True(domain.FillRequiredGroupsFromTemplates(Array.Empty<string>()));
        Assert.Empty(domain.RequiredGroups);
    }

    /// <summary>
    /// Список шаблонов с пустым именем отклоняется, список групп не заполняется.
    /// Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_OnWindows_InvalidTemplate_ReturnsFalse()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!;

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("company.local", "abcdef012345", encryptedUser, encryptedPassword);

        string[] templates = ["WebShelf-{InstanceIdShort}-Users", "   "];

        Assert.False(domain.FillRequiredGroupsFromTemplates(templates));
        Assert.Empty(domain.RequiredGroups);
    }

    /// <summary>
    /// Шаблон, совсем не содержащий заполнителя, используется как имя группы
    /// без изменений и попадает в список наряду с шаблонами с заполнителем.
    /// Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_OnWindows_TemplateWithoutPlaceholder_UsedAsIs()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!;

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("company.local", "abcdef012345", encryptedUser, encryptedPassword);

        string[] templates = ["WebShelf-{InstanceIdShort}-Users", "WebShelf-Common-Group"];

        Assert.True(domain.FillRequiredGroupsFromTemplates(templates));
        Assert.Equal(2, domain.RequiredGroups.Count);
        Assert.Contains("WebShelf-abcdef012345-Users", domain.RequiredGroups);
        Assert.Contains("WebShelf-Common-Group", domain.RequiredGroups);
    }

    /// <summary>
    /// Шаблон с некорректным заполнителем (опечатка, незакрытая скобка, лишний
    /// заполнитель) в список групп не добавляется: в лог пишется предупреждение,
    /// формирование списка продолжается. Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_OnWindows_InvalidPlaceholder_TemplateSkipped()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!;

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("company.local", "abcdef012345", encryptedUser, encryptedPassword);

        string[] templates =
        [
            "WebShelf-{InstanceIdShort}-Users",         // корректный шаблон
            "WebShelf-{InstanseIdShort}-Administrator", // опечатка в заполнителе
            "WebShelf-{InstanceIdShort-Manager",        // незакрытый заполнитель
            "WebShelf-{InstanceIdShort}-{Role}"         // второй заполнитель некорректен
        ];

        Assert.True(domain.FillRequiredGroupsFromTemplates(templates));
        Assert.Single(domain.RequiredGroups);
        Assert.Contains("WebShelf-abcdef012345-Users", domain.RequiredGroups);
    }

    /// <summary>
    /// Список шаблонов, состоящий только из шаблонов с опечаткой в заполнителе,
    /// не считается ошибкой: метод возвращает true, список групп остаётся пустым
    /// (по каждому шаблону пишется предупреждение). Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_OnWindows_AllTemplatesWithTypo_ListStaysEmpty()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!;

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("company.local", "abcdef012345", encryptedUser, encryptedPassword);

        string[] templates =
        [
            "WebShelf-{InstanseIdShort}-Administrator", // опечатка в заполнителе
            "WebShelf-{InstanceIdShort-Manager"         // незакрытый заполнитель
        ];

        Assert.True(domain.FillRequiredGroupsFromTemplates(templates));
        Assert.Empty(domain.RequiredGroups);
    }

    /// <summary>
    /// Смешанный список шаблонов: корректные шаблоны и шаблон без заполнителя
    /// попадают в список, шаблон с опечаткой пропускается, дубликаты убираются.
    /// Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_OnWindows_MixedTemplates_OnlyValidAdded()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!;

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("company.local", "abcdef012345", encryptedUser, encryptedPassword);

        string[] templates =
        [
            "WebShelf-{InstanceIdShort}-Users",         // корректный шаблон
            "WebShelf-Common-Group",                    // без заполнителя
            "WebShelf-{InstanseIdShort}-Administrator", // опечатка — пропускается
            "webshelf-{InstanceIdShort}-USERS"          // дубликат первого
        ];

        Assert.True(domain.FillRequiredGroupsFromTemplates(templates));
        Assert.Equal(2, domain.RequiredGroups.Count);
        Assert.Contains("WebShelf-abcdef012345-Users", domain.RequiredGroups);
        Assert.Contains("WebShelf-Common-Group", domain.RequiredGroups);
    }

    /// <summary>
    /// Незаданный список шаблонов отклоняется, список групп не заполняется.
    /// Выполняется только на Windows.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_OnWindows_NullTemplates_ReturnsFalse()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!;

        string encryptedUser = EncryptionService.Encrypt("svc_webshelf", key);
        string encryptedPassword = EncryptionService.Encrypt("TestPassword123!", key);

        Domain domain = new Domain("company.local", "abcdef012345", encryptedUser, encryptedPassword);

        Assert.False(domain.FillRequiredGroupsFromTemplates(null!));
        Assert.Empty(domain.RequiredGroups);
    }

    #endregion
}
