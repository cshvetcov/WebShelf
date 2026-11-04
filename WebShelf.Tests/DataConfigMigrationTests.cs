using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Characterization-тесты миграции учётных данных на уровне
/// <see cref="Data.ReadConfigAsync"/> (шаг 0 дорожной карты декомпозиции).
/// Фиксируют фактическое поведение чтения Server.conf: перенос открытых
/// учётных данных в защищённые с затиранием открытых, отсутствие
/// перезаписи файла при чистых защищённых значениях и асимметрию
/// очистки остаточных открытых значений (пробел У1 — будет закрыт
/// в шаге 6).
/// Сценарии требуют реального мастер-ключа (HKCU + DPAPI), поэтому
/// выполняются только на Windows и автоматически пропускаются на других
/// платформах. Домен и БД недоступны в тестовом окружении — миграция
/// происходит до проверок их доступности, что и проверяется тестами.
/// </summary>
public class DataConfigMigrationTests
{
    /// <summary>
    /// Тестовый домен: зарезервированная TLD .invalid не резолвится —
    /// проверка доступности AD гарантированно завершается отказом уже
    /// после того, как миграция учётных данных выполнена.
    /// </summary>
    private const string UnreachableDomain = "webshelf-test.invalid";

    /// <summary>
    /// Открытые учётные данные домена при чтении конфигурации
    /// шифруются, записываются в sdomainuser/sdomainpass, открытые
    /// значения затираются. Миграция выполняется до проверки
    /// доступности AD: файл переписан, хотя конфигурация в целом
    /// не загружается (домен недоступен).
    /// </summary>
    [Fact]
    public async Task ReadConfigAsync_PlainDomainCredentials_MigratedAndWiped()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");
        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!; // SkipUnless гарантирует ненулевое значение при продолжении

        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                $"domainname={UnreachableDomain}",
                "domainuser=svc-account",
                "domainpass=svc-secret",
                "scheme=http",
                "port=38080");

            Data data = new Data(path);
            data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");

            bool result = await data.ReadConfigAsync();

            // Домен недоступен — конфигурация не загружена,
            // но миграция уже выполнена до проверки доступности AD
            Assert.False(result);

            string[] lines = File.ReadAllLines(path);
            Assert.Contains("domainuser=", lines);
            Assert.Contains("domainpass=", lines);
            Assert.DoesNotContain("domainuser=svc-account", lines);
            Assert.DoesNotContain("domainpass=svc-secret", lines);

            // Записанные защищённые значения расшифровываются
            // мастер-ключом в исходные открытые
            string? secureUser = lines
                .FirstOrDefault(l => l.StartsWith("sdomainuser=", StringComparison.Ordinal))
                ?["sdomainuser=".Length..];
            string? securePass = lines
                .FirstOrDefault(l => l.StartsWith("sdomainpass=", StringComparison.Ordinal))
                ?["sdomainpass=".Length..];

            Assert.False(string.IsNullOrWhiteSpace(secureUser));
            Assert.False(string.IsNullOrWhiteSpace(securePass));
            Assert.Equal("svc-account", EncryptionService.Decrypt(secureUser!, key));
            Assert.Equal("svc-secret", EncryptionService.Decrypt(securePass!, key));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Конфигурация только с валидными защищёнными значениями
    /// (без открытых) не переписывается: файл байтово идентичен
    /// до и после чтения.
    /// </summary>
    [Fact]
    public async Task ReadConfigAsync_SecureCredentialsOnly_FileNotRewritten()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");
        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!; // SkipUnless гарантирует ненулевое значение при продолжении

        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                $"domainname={UnreachableDomain}",
                $"sdomainuser={EncryptionService.Encrypt("svc-account", key)}",
                $"sdomainpass={EncryptionService.Encrypt("svc-secret", key)}",
                "scheme=http",
                "port=38080");

            byte[] before = File.ReadAllBytes(path);

            Data data = new Data(path);
            data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");

            bool result = await data.ReadConfigAsync();

            Assert.False(result); // домен недоступен
            Assert.Equal(before, File.ReadAllBytes(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Пробел У1 (фиксация перед исправлением в шаге 6): при одновременно
    /// непустых открытых и валидных защищённых доменных значениях
    /// защищённая ветка TryInitDomain открытые значения НЕ затирает —
    /// они остаются в файле в открытом виде, файл не переписывается.
    /// ОЖИДАНИЕ БУДЕТ ИЗМЕНЕНО В ШАГЕ 6 (улучшение У1): открытые значения
    /// станут затираться, файл — переписываться один раз.
    /// </summary>
    [Fact]
    public async Task ReadConfigAsync_SecureDomainCredentials_PlainLeftovers_Remain_UntilStep6()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");
        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!; // SkipUnless гарантирует ненулевое значение при продолжении

        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                $"domainname={UnreachableDomain}",
                $"sdomainuser={EncryptionService.Encrypt("svc-account", key)}",
                $"sdomainpass={EncryptionService.Encrypt("svc-secret", key)}",
                "domainuser=LEFTOVER-USER",
                "domainpass=LEFTOVER-SECRET",
                "scheme=http",
                "port=38080");

            byte[] before = File.ReadAllBytes(path);

            Data data = new Data(path);
            data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");

            bool result = await data.ReadConfigAsync();

            Assert.False(result); // домен недоступен

            // Документация текущего поведения (асимметрия У1):
            // непустые открытые значения остаются в файле без изменений
            Assert.Equal(before, File.ReadAllBytes(path));
            Assert.Contains("domainuser=LEFTOVER-USER", File.ReadAllLines(path));
            Assert.Contains("domainpass=LEFTOVER-SECRET", File.ReadAllLines(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Пара БД, в отличие от доменной пары, уже зачищает остаточные
    /// открытые значения: при валидных sdbuser/sdbpass и непустых
    /// dbuser/dbpass защищённая ветка перезаписывает файл, затирая
    /// открытые значения (симметричное поведение, ожидаемое от У1
    /// после шага 6).
    /// </summary>
    [Fact]
    public async Task ReadConfigAsync_SecureDbCredentials_PlainLeftovers_Wiped()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");
        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!; // SkipUnless гарантирует ненулевое значение при продолжении

        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            string encryptedDbUser = EncryptionService.Encrypt("svc-db", key);
            string encryptedDbPass = EncryptionService.Encrypt("db-secret", key);
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                $"domainname={UnreachableDomain}",
                "sdbuser=" + encryptedDbUser,
                "sdbpass=" + encryptedDbPass,
                "dbuser=LEFTOVER-USER",
                "dbpass=LEFTOVER-SECRET",
                "dbhost=127.0.0.1",
                "dbport=1",
                "dbname=webshelf_test",
                "scheme=http",
                "port=38080");

            Data data = new Data(path);
            data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");

            bool result = await data.ReadConfigAsync();

            // Домен недоступен, БД по 127.0.0.1:1 недоступна —
            // но очистка остаточных dbuser/dbpass уже выполнена
            Assert.False(result);

            string[] lines = File.ReadAllLines(path);
            Assert.Contains("dbuser=", lines);
            Assert.Contains("dbpass=", lines);
            Assert.DoesNotContain("dbuser=LEFTOVER-USER", lines);
            Assert.DoesNotContain("dbpass=LEFTOVER-SECRET", lines);

            // Защищённые значения сохранены без изменений
            Assert.Contains("sdbuser=" + encryptedDbUser, lines);
            Assert.Contains("sdbpass=" + encryptedDbPass, lines);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Пара TLS-сертификата, как и пара БД, зачищает остаточное открытое
    /// значение: при валидном scertpass и непустом certpass защищённая
    /// ветка перезаписывает файл, затирая certpass. Затирание происходит
    /// до загрузки PFX-файла, поэтому сертификат в тесте может быть
    /// некорректным (загрузка завершится отказом уже после записи).
    /// </summary>
    [Fact]
    public async Task ReadConfigAsync_SecureCertPass_PlainLeftover_Wiped()
    {
        Assert.SkipWhen(!OperatingSystem.IsWindows(), "Требуется Windows: мастер-ключ хранится в HKCU под защитой DPAPI.");
        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        Assert.SkipUnless(masterKey is not null, "Мастер-ключ недоступен.");
        byte[] key = masterKey!; // SkipUnless гарантирует ненулевое значение при продолжении

        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            string certPath = Path.Combine(directory, "cert.pfx");
            File.WriteAllBytes(certPath, "not-a-real-pfx"u8.ToArray());
            string encryptedCertPass = EncryptionService.Encrypt("cert-secret", key);

            DataConfigTestHelpers.WriteUtf8NoBom(path,
                $"domainname={UnreachableDomain}",
                "certpath=" + certPath,
                "scertpass=" + encryptedCertPass,
                "certpass=LEFTOVER-SECRET",
                "scheme=https",
                "port=38080");

            Data data = new Data(path);
            data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");

            bool result = await data.ReadConfigAsync();

            // Домен недоступен, PFX некорректен — но очистка остаточного
            // certpass уже выполнена до загрузки сертификата
            Assert.False(result);

            string[] lines = File.ReadAllLines(path);
            Assert.Contains("certpass=", lines);
            Assert.DoesNotContain("certpass=LEFTOVER-SECRET", lines);
            Assert.Contains("scertpass=" + encryptedCertPass, lines);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
