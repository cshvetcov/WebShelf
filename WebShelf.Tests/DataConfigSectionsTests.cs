using System.Security.Cryptography.X509Certificates;
using WebShelf.Classes.Crypto;
using WebShelf.Classes.DB;
using WebShelf.Classes.DC;
using WebShelf.Classes.Service;
using WebShelf.Classes.Service.Configuration;
using WebShelf.Classes.Service.Configuration.Sections;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Прямые тесты инициализаторов секций конфигурации, вынесенных из Data
/// шагом 6 дорожной карты декомпозиции (DomainSection, DatabaseSection,
/// CertificateSection — точка решения о секциях). Покрывают ветки,
/// не требующие мастер-ключа и обращения к сети, поэтому выполняются
/// на любой платформе (шаг 8 декомпозиции: секции получают криптографию
/// параметрами — подмена хранилища ключей и реальный движок); сценарии
/// с шифрованием и миграцией учётных данных остаются на уровне
/// <see cref="Data.ReadConfigAsync"/> в DataConfigMigrationTests
/// (после шага 8 — на подмене хранилища, платформонезависимые)
/// и у перенесённых characterization-тестов записи.
/// </summary>
public class DataConfigSectionsTests
{
    /// <summary>
    /// Отсутствие обязательного ключа domainname — отказ инициализации
    /// секции домена (null) без обращения к мастер-ключу.
    /// </summary>
    [Fact]
    public void TryInitDomain_MissingDomainName_ReturnsNull()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            SecureCredentialsWriter writer = new(Path.Combine(directory, "Server.conf"));

            Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
            {
                ["scheme"] = "http",
            };

            Domain? domain = DomainSection.TryInitDomain(
                config, "0123456789ab", writer, new CryptoTestFakes.FakeKeyStore(), new CryptoEngine());

            Assert.Null(domain);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Пустое значение domainname — отказ инициализации секции домена (null)
    /// без обращения к мастер-ключу.
    /// </summary>
    [Fact]
    public void TryInitDomain_EmptyDomainName_ReturnsNull()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            SecureCredentialsWriter writer = new(Path.Combine(directory, "Server.conf"));

            Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
            {
                ["domainname"] = "   ",
            };

            Domain? domain = DomainSection.TryInitDomain(
                config, "0123456789ab", writer, new CryptoTestFakes.FakeKeyStore(), new CryptoEngine());

            Assert.Null(domain);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Отсутствие обязательного ключа dbhost — отказ инициализации секции БД
    /// (null) без обращения к мастер-ключу и сети.
    /// </summary>
    [Fact]
    public async Task TryInitDatabaseAsync_MissingDbHost_ReturnsNull()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            SecureCredentialsWriter writer = new(Path.Combine(directory, "Server.conf"));

            Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
            {
                ["dbname"] = "webshelf_test",
            };

            Database? database = await DatabaseSection.TryInitDatabaseAsync(
                config, writer, new CryptoTestFakes.FakeKeyStore(), new CryptoEngine());

            Assert.Null(database);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// При схеме http TLS-сертификат не требуется: инициализация секции
    /// завершается успехом без загрузки файла и мастер-ключа,
    /// сертификат не возвращается.
    /// </summary>
    [Fact]
    public void TryInitCertificate_SchemeHttp_ReturnsTrueWithoutCertificate()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            SecureCredentialsWriter writer = new(Path.Combine(directory, "Server.conf"));

            Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase)
            {
                ["scheme"] = "http",
            };

            bool result = CertificateSection.TryInitCertificate(
                config, "http", writer, new CryptoTestFakes.FakeKeyStore(), new CryptoEngine(), out X509Certificate2? certificate);

            Assert.True(result);
            Assert.Null(certificate);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Инициализаторы секций отклоняют null-криптографические зависимости
    /// (новые публичные границы шага 8): TryInitDomain, TryInitDatabaseAsync
    /// и TryInitCertificate завершаются ArgumentNullException до любой
    /// обработки конфигурации. Проверяется до обращения к файлу конфигурации —
    /// временный каталог не требуется.
    /// </summary>
    [Fact]
    public async Task TryInitSections_NullCryptoDependencies_ThrowArgumentNullException()
    {
        SecureCredentialsWriter writer = new(Path.Combine(Path.GetTempPath(), "WebShelfStep8NullCheck", "Server.conf"));
        Dictionary<string, string> config = new(StringComparer.OrdinalIgnoreCase);

        Assert.Throws<ArgumentNullException>(() =>
            DomainSection.TryInitDomain(config, "0123456789ab", writer, null!, new CryptoEngine()));
        Assert.Throws<ArgumentNullException>(() =>
            DomainSection.TryInitDomain(config, "0123456789ab", writer, new CryptoTestFakes.FakeKeyStore(), null!));

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            DatabaseSection.TryInitDatabaseAsync(config, writer, null!, new CryptoEngine()));
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            DatabaseSection.TryInitDatabaseAsync(config, writer, new CryptoTestFakes.FakeKeyStore(), null!));

        Assert.Throws<ArgumentNullException>(() =>
            CertificateSection.TryInitCertificate(config, "https", writer, null!, new CryptoEngine(), out _));
        Assert.Throws<ArgumentNullException>(() =>
            CertificateSection.TryInitCertificate(config, "https", writer, new CryptoTestFakes.FakeKeyStore(), null!, out _));
    }
}
