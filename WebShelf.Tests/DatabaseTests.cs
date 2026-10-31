using Npgsql;
using WebShelf.Classes.DB;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты класса Database: валидация параметров конструктора.
/// Проверки ArgumentException выполняются до обращения к мастер-ключу,
/// поэтому работают на любой ОС. Полный конструктор (расшифровка учётных
/// данных, создание NpgsqlDataSource) требует Windows-хранилища мастер-ключа.
/// </summary>
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
            new Database(host!, 5432, "webshelf", SslMode.Require, "encUser", "encPass"));
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
            new Database("localhost", port, "webshelf", SslMode.Require, "encUser", "encPass"));
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
            new Database("localhost", 5432, databaseName!, SslMode.Require, "encUser", "encPass"));
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
            new Database("localhost", 5432, "webshelf", SslMode.Require, encryptedUser!, encryptedPassword!));
    }

    /// <summary>
    /// Полный конструктор на Windows: расшифровывает учётные данные,
    /// создаёт NpgsqlDataSource и сохраняет параметры подключения.
    /// </summary>
    [Fact]
    public async Task Constructor_OnWindows_ValidParameters_InitializesConnectionSource()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!; // SkipUnless гарантирует ненулевое значение при продолжении

        string encryptedUser = EncryptionService.Encrypt("db_webshelf", key);
        string encryptedPass = EncryptionService.Encrypt("TestPassword123!", key);

        await using Database database = new Database(
            "localhost", 5432, "webshelf_test", SslMode.Prefer, encryptedUser, encryptedPass);

        Assert.Equal("localhost", database.Host);
        Assert.Equal(5432, database.Port);
        Assert.Equal("webshelf_test", database.DatabaseName);
        Assert.Equal(SslMode.Prefer, database.SslMode);
    }

    /// <summary>
    /// Повторный Dispose идемпотентен и не выбрасывает исключений.
    /// </summary>
    [Fact]
    public void Dispose_CalledTwice_IsIdempotent()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!; // SkipUnless гарантирует ненулевое значение при продолжении

        string encryptedUser = EncryptionService.Encrypt("db_webshelf", key);
        string encryptedPass = EncryptionService.Encrypt("TestPassword123!", key);

        Database database = new Database(
            "localhost", 5432, "webshelf_test", SslMode.Prefer, encryptedUser, encryptedPass);

        database.Dispose();
        database.Dispose();
    }
}
