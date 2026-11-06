using WebShelf.Classes.Crypto;
using WebShelf.Classes.DC;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты класса Domain: валидация аргументов конструктора, построение LDAP-пути
/// (полный конструктор). Тесты формирования списка групп безопасности из шаблонов
/// имён и обеспечения их существования перенесены в AdGroupManagerTests
/// (шаг 7 декомпозиции). Шаг 8 декомпозиции (улучшение У3): криптография
/// поступает через конструктор инстансными зависимостями — полный конструктор
/// тестируется с подменой хранилища ключей (<see cref="CryptoTestFakes.FakeKeyStore"/>)
/// и реальным движком на любой ОС, без обращения к реестру и DPAPI.
/// </summary>
/// <remarks>
/// Класс входит в непараллельную коллекцию <see cref="KeyStoreTests.MasterKeyRegistryCollection"/>
/// (сохранена сериализация с реестровыми тестами KeyStoreTests; собственно
/// реестр тесты этого класса после шага 8 не используют).
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
            new Domain(domain!, "abcdef012345", "encryptedUser", "encryptedPassword", new CryptoTestFakes.FakeKeyStore(), new CryptoEngine()));
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
            new Domain("company.local", instanceIdShort!, "encryptedUser", "encryptedPassword", new CryptoTestFakes.FakeKeyStore(), new CryptoEngine()));
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
            new Domain("company.local", "abcdef012345", encryptedUser!, encryptedPassword!, new CryptoTestFakes.FakeKeyStore(), new CryptoEngine()));
    }

    /// <summary>
    /// Конструктор отклоняет null-хранилище ключей (новая публичная граница
    /// шага 8: криптографические зависимости обязательны).
    /// </summary>
    [Fact]
    public void Constructor_NullKeyStore_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new Domain("company.local", "abcdef012345", "encryptedUser", "encryptedPassword", null!, new CryptoEngine()));
    }

    /// <summary>
    /// Конструктор отклоняет null-движок шифрования (новая публичная граница
    /// шага 8: криптографические зависимости обязательны).
    /// </summary>
    [Fact]
    public void Constructor_NullCryptoEngine_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new Domain("company.local", "abcdef012345", "encryptedUser", "encryptedPassword", new CryptoTestFakes.FakeKeyStore(), null!));
    }

    #endregion

    #region Полный конструктор (фейковое хранилище ключей + реальный движок)

    /// <summary>
    /// Полный конструктор расшифровывает учётные данные, нормализует логин
    /// и строит LDAP-путь корня домена. Мастер-ключ поступает из подмены
    /// хранилища (улучшение У3 шага 8) — реестр и DPAPI не затрагиваются,
    /// тест выполняется на любой ОС (ранее — только Windows).
    /// </summary>
    [Fact]
    public void Constructor_WithFakeKeyStore_ValidCredentials_BuildsDomain()
    {
        KeyStore keyStore = new CryptoTestFakes.FakeKeyStore();
        CryptoEngine cryptoEngine = new();
        byte[] key = keyStore.EnsureMasterKey()!;

        string encryptedUser = cryptoEngine.Encrypt("svc_webshelf", key, CryptoContexts.DomainUser);
        string encryptedPassword = cryptoEngine.Encrypt("TestPassword123!", key, CryptoContexts.DomainPassword);

        Domain domain = new("company.local", "abcdef012345", encryptedUser, encryptedPassword, keyStore, cryptoEngine);

        Assert.Equal("company.local", domain.Name);
        Assert.Equal("LDAP://company.local/DC=company,DC=local", domain.Path);
        // Логин нормализуется к формату username@domain
        Assert.Equal("svc_webshelf@company.local", domain.GetDecryptedUser());
    }

    /// <summary>
    /// Конструктор отклоняет учётные данные, не поддающиеся расшифровке.
    /// Мастер-ключ поступает из подмены хранилища — реестр и DPAPI
    /// не затрагиваются, тест выполняется на любой ОС (ранее — только Windows).
    /// </summary>
    [Fact]
    public void Constructor_InvalidEncryptedData_ThrowsInvalidOperationException()
    {
        // Корректная Base64, но данные не зашифрованы сервисом — MAC не сойдётся
        string garbageUser = Convert.ToBase64String(new byte[65]);

        Assert.Throws<InvalidOperationException>(() =>
            new Domain("company.local", "abcdef012345", garbageUser, garbageUser, new CryptoTestFakes.FakeKeyStore(), new CryptoEngine()));
    }

    #endregion
}
