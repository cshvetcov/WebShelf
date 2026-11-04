using WebShelf.Classes.DC;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты класса Domain: валидация аргументов конструктора, построение LDAP-пути
/// (полный конструктор — только Windows), а также формирование списка необходимых
/// групп безопасности из шаблонов имён (подстановка заполнителя {InstanceIdShort},
/// отбраковка шаблонов с опечаткой).
/// </summary>
/// <remarks>
/// Класс входит в непараллельную коллекцию <see cref="KeyStoreTests.MasterKeyRegistryCollection"/>:
/// тесты используют реестровый мастер-ключ, с которым работают тесты KeyStoreTests
/// (временная подмена значения реестра исключает параллельное выполнение).
/// </remarks>
[Collection(KeyStoreTests.MasterKeyRegistryCollection)]
public class DomainTests
{
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
