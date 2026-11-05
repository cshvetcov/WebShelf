using Npgsql;
using WebShelf.Classes.Crypto;
using WebShelf.Classes.DB;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты класса Database: валидация параметров конструктора.
/// Проверки ArgumentException выполняются до обращения к мастер-ключу,
/// поэтому работают на любой ОС. Полный конструктор (расшифровка учётных
/// данных, создание NpgsqlDataSource) тестируется с подменой хранилища
/// ключей (<see cref="CryptoTestFakes.FakeKeyStore"/>) и реальным движком
/// — улучшение У3 шага 8: реестр и DPAPI не затрагиваются, создание
/// <see cref="NpgsqlDataSource"/> не подключается к сети.
/// </summary>
/// <remarks>
/// Класс входит в непараллельную коллекцию <see cref="KeyStoreTests.MasterKeyRegistryCollection"/>
/// (сохранена сериализация с реестровыми тестами KeyStoreTests; собственно
/// реестр тесты этого класса после шага 8 не используют).
/// </remarks>
[Collection(KeyStoreTests.MasterKeyRegistryCollection)]
public class DatabaseTests
{
    /// <summary>
    /// Конструктор отклоняет пустой хост.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_EmptyHost_ThrowsArgumentException(string? host)
    {
        Assert.Throws<ArgumentException>(() =>
            new Database(host!, 5432, "webshelf", SslMode.Require, "encUser", "encPass", new CryptoTestFakes.FakeKeyStore(), new CryptoEngine()));
    }

    /// <summary>
    /// Конструктор отклоняет порт вне диапазона 1–65535.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    public void Constructor_InvalidPort_ThrowsArgumentException(int port)
    {
        Assert.Throws<ArgumentException>(() =>
            new Database("localhost", port, "webshelf", SslMode.Require, "encUser", "encPass", new CryptoTestFakes.FakeKeyStore(), new CryptoEngine()));
    }

    /// <summary>
    /// Конструктор отклоняет пустое имя базы данных.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_EmptyDatabaseName_ThrowsArgumentException(string? databaseName)
    {
        Assert.Throws<ArgumentException>(() =>
            new Database("localhost", 5432, databaseName!, SslMode.Require, "encUser", "encPass", new CryptoTestFakes.FakeKeyStore(), new CryptoEngine()));
    }

    /// <summary>
    /// Конструктор отклоняет пустые зашифрованные учётные данные.
    /// </summary>
    [Theory]
    [InlineData(null, "encPass")]
    [InlineData("", "encPass")]
    [InlineData("   ", "encPass")]
    [InlineData("encUser", null)]
    [InlineData("encUser", "")]
    [InlineData("encUser", "   ")]
    public void Constructor_EmptyEncryptedCredentials_ThrowsArgumentException(
        string? encryptedUser, string? encryptedPassword)
    {
        Assert.Throws<ArgumentException>(() =>
            new Database("localhost", 5432, "webshelf", SslMode.Require, encryptedUser!, encryptedPassword!, new CryptoTestFakes.FakeKeyStore(), new CryptoEngine()));
    }

    /// <summary>
    /// Конструктор отклоняет null-хранилище ключей (новая публичная граница
    /// шага 8: криптографические зависимости обязательны).
    /// </summary>
    [Fact]
    public void Constructor_NullKeyStore_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new Database("localhost", 5432, "webshelf", SslMode.Require, "encUser", "encPass", null!, new CryptoEngine()));
    }

    /// <summary>
    /// Конструктор отклоняет null-движок шифрования (новая публичная граница
    /// шага 8: криптографические зависимости обязательны).
    /// </summary>
    [Fact]
    public void Constructor_NullCryptoEngine_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new Database("localhost", 5432, "webshelf", SslMode.Require, "encUser", "encPass", new CryptoTestFakes.FakeKeyStore(), null!));
    }

    /// <summary>
    /// Полный конструктор: расшифровывает учётные данные ключом из подмены
    /// хранилища, создаёт NpgsqlDataSource и сохраняет параметры подключения.
    /// Реестр и DPAPI не затрагиваются — тест выполняется на любой ОС
    /// (ранее — только Windows).
    /// </summary>
    [Fact]
    public async Task Constructor_WithFakeKeyStore_ValidParameters_InitializesConnectionSource()
    {
        KeyStore keyStore = new CryptoTestFakes.FakeKeyStore();
        CryptoEngine cryptoEngine = new();
        byte[] key = keyStore.EnsureMasterKey()!;

        string encryptedUser = cryptoEngine.Encrypt("db_webshelf", key);
        string encryptedPass = cryptoEngine.Encrypt("TestPassword123!", key);

        await using Database database = new(
            "localhost", 5432, "webshelf_test", SslMode.Prefer, encryptedUser, encryptedPass, keyStore, cryptoEngine);

        Assert.Equal("localhost", database.Host);
        Assert.Equal(5432, database.Port);
        Assert.Equal("webshelf_test", database.DatabaseName);
        Assert.Equal(SslMode.Prefer, database.SslMode);
    }

    /// <summary>
    /// Повторный Dispose идемпотентен и не выбрасывает исключений.
    /// Мастер-ключ поступает из подмены хранилища — реестр и DPAPI
    /// не затрагиваются (ранее — только Windows).
    /// </summary>
    [Fact]
    public void Dispose_CalledTwice_IsIdempotent()
    {
        KeyStore keyStore = new CryptoTestFakes.FakeKeyStore();
        CryptoEngine cryptoEngine = new();
        byte[] key = keyStore.EnsureMasterKey()!;

        string encryptedUser = cryptoEngine.Encrypt("db_webshelf", key);
        string encryptedPass = cryptoEngine.Encrypt("TestPassword123!", key);

        Database database = new(
            "localhost", 5432, "webshelf_test", SslMode.Prefer, encryptedUser, encryptedPass, keyStore, cryptoEngine);

        database.Dispose();
        database.Dispose();
    }
}
