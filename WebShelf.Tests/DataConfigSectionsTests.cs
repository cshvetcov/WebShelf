using System.Security.Cryptography.X509Certificates;
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
/// не требующие мастер-ключа (HKCU + DPAPI) и обращения к сети,
/// поэтому выполняются на любой платформе; сценарии с реальным
/// шифрованием и миграцией учётных данных остаются на уровне
/// <see cref="Data.ReadConfigAsync"/> в DataConfigMigrationTests
/// (Windows-only) и у перенесённых characterization-тестов записи.
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

            Domain? domain = DomainSection.TryInitDomain(config, "0123456789ab", writer);

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

            Domain? domain = DomainSection.TryInitDomain(config, "0123456789ab", writer);

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

            Database? database = await DatabaseSection.TryInitDatabaseAsync(config, writer);

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
                config, "http", writer, out X509Certificate2? certificate);

            Assert.True(result);
            Assert.Null(certificate);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
