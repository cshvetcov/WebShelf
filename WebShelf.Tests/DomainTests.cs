using WebShelf.Classes.DC;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты класса Domain: нормализация имён пользователей к формату username@domain,
/// построение LDAP-пути и валидация аргументов конструктора.
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
}
