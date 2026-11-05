using WebShelf.Classes.DC;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты класса Domain: валидация аргументов конструктора, построение LDAP-пути
/// (полный конструктор — только Windows). Тесты формирования списка групп
/// безопасности из шаблонов имён и обеспечения их существования перенесены
/// в AdGroupManagerTests (шаг 7 декомпозиции).
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
}
