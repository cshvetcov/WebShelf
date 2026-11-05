using WebShelf.Classes.Crypto;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Characterization-тесты миграции учётных данных на уровне
/// <see cref="Data.ReadConfigAsync"/> (шаг 0 дорожной карты декомпозиции).
/// Фиксируют фактическое поведение чтения Server.conf: перенос открытых
/// учётных данных в защищённые с затиранием открытых, отсутствие
/// перезаписи файла при чистых защищённых значениях и симметричную
/// очистку остаточных открытых значений (У1 закрыт в шаге 6:
/// доменная пара ведёт себя как пары БД и TLS).
/// Шаг 8 декомпозиции (улучшение У3): мастер-ключ поступает из подмены
/// хранилища (<see cref="CryptoTestFakes.FakeKeyStore"/>), шифрование
/// и расшифровка — реальным <see cref="CryptoEngine"/>; реестр и DPAPI
/// не затрагиваются, поэтому тесты выполняются на любой платформе
/// (ранее — только Windows). Домен и БД недоступны в тестовом окружении —
/// миграция происходит до проверок их доступности, что и проверяется
/// тестами; реальные сценарии хранилища остаются в KeyStoreTests
/// (Windows-прогон).
/// </summary>
/// <remarks>
/// Класс входит в непараллельную коллекцию <see cref="KeyStoreTests.MasterKeyRegistryCollection"/>
/// (сохранена сериализация с реестровыми тестами KeyStoreTests; собственно
/// реестр тесты этого класса после шага 8 не используют).
/// </remarks>
[Collection(KeyStoreTests.MasterKeyRegistryCollection)]
public class DataConfigMigrationTests
{
    /// <summary>
    /// Тестовый домен: зарезервированная TLD .invalid не резолвится —
    /// проверка доступности AD гарантированно завершается отказом уже
    /// после того, как миграция учётных данных выполнена.
    /// </summary>
    private const string UnreachableDomain = "webshelf-test.invalid";

    /// <summary>
    /// Создаёт пару «хранилище + движок» для теста: подмена хранилища
    /// возвращает синтетический мастер-ключ, движок — реальный.
    /// </summary>
    /// <returns>Кортеж: хранилище ключей, движок, синтетический мастер-ключ.</returns>
    private static (KeyStore KeyStore, CryptoEngine CryptoEngine, byte[] Key) CreateCrypto()
    {
        KeyStore keyStore = new CryptoTestFakes.FakeKeyStore();
        CryptoEngine cryptoEngine = new CryptoEngine();
        byte[] key = keyStore.EnsureMasterKey()!;

        return (keyStore, cryptoEngine, key);
    }

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
        (KeyStore keyStore, CryptoEngine cryptoEngine, byte[] key) = CreateCrypto();

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

            Data data = new Data(keyStore, cryptoEngine, path);
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
            Assert.Equal("svc-account", cryptoEngine.Decrypt(secureUser!, key));
            Assert.Equal("svc-secret", cryptoEngine.Decrypt(securePass!, key));
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
        (KeyStore keyStore, CryptoEngine cryptoEngine, byte[] key) = CreateCrypto();

        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                $"domainname={UnreachableDomain}",
                $"sdomainuser={cryptoEngine.Encrypt("svc-account", key)}",
                $"sdomainpass={cryptoEngine.Encrypt("svc-secret", key)}",
                "scheme=http",
                "port=38080");

            byte[] before = File.ReadAllBytes(path);

            Data data = new Data(keyStore, cryptoEngine, path);
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
    /// Улучшение У1 (закрыто в шаге 6, ранее тест фиксировал асимметрию
    /// под именем …PlainLeftovers_Remain_UntilStep6): при одновременно
    /// непустых открытых и валидных защищённых доменных значениях
    /// защищённая ветка TryInitDomain затирает открытые значения —
    /// поведение симметрично парам БД и TLS. Затирание выполняется
    /// до проверки доступности AD: файл переписан, хотя конфигурация
    /// в целом не загружается (домен недоступен); защищённые значения
    /// сохраняются без изменений.
    /// </summary>
    [Fact]
    public async Task ReadConfigAsync_SecureDomainCredentials_PlainLeftovers_Wiped()
    {
        (KeyStore keyStore, CryptoEngine cryptoEngine, byte[] key) = CreateCrypto();

        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            string encryptedUser = cryptoEngine.Encrypt("svc-account", key);
            string encryptedPass = cryptoEngine.Encrypt("svc-secret", key);
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                $"domainname={UnreachableDomain}",
                "sdomainuser=" + encryptedUser,
                "sdomainpass=" + encryptedPass,
                "domainuser=LEFTOVER-USER",
                "domainpass=LEFTOVER-SECRET",
                "scheme=http",
                "port=38080");

            Data data = new Data(keyStore, cryptoEngine, path);
            data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");

            bool result = await data.ReadConfigAsync();

            // Домен недоступен — конфигурация не загружена,
            // но очистка остаточных значений уже выполнена (как у пар БД и TLS)
            Assert.False(result);

            string[] lines = File.ReadAllLines(path);
            Assert.Contains("domainuser=", lines);
            Assert.Contains("domainpass=", lines);
            Assert.DoesNotContain("domainuser=LEFTOVER-USER", lines);
            Assert.DoesNotContain("domainpass=LEFTOVER-SECRET", lines);

            // Защищённые значения сохранены без изменений
            Assert.Contains("sdomainuser=" + encryptedUser, lines);
            Assert.Contains("sdomainpass=" + encryptedPass, lines);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Идемпотентность миграции после У1 (шаг 6): файл переписывается ровно
    /// один раз — при первом чтении, обнаружившем непустые открытые значения
    /// при валидных защищённых. Повторное чтение конфигурации с чистыми
    /// защищёнными значениями файл не переписывает (байтово идентичен).
    /// </summary>
    [Fact]
    public async Task ReadConfigAsync_AfterLeftoverWipe_SecondReadDoesNotRewriteFile()
    {
        (KeyStore keyStore, CryptoEngine cryptoEngine, byte[] key) = CreateCrypto();

        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            string encryptedUser = cryptoEngine.Encrypt("svc-account", key);
            string encryptedPass = cryptoEngine.Encrypt("svc-secret", key);
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                $"domainname={UnreachableDomain}",
                "sdomainuser=" + encryptedUser,
                "sdomainpass=" + encryptedPass,
                "domainuser=LEFTOVER-USER",
                "domainpass=LEFTOVER-SECRET",
                "scheme=http",
                "port=38080");

            Data data = new Data(keyStore, cryptoEngine, path);
            data.SetInstanceId("0123456789ABCDEFGHIJKLMNO");

            bool firstResult = await data.ReadConfigAsync();
            Assert.False(firstResult); // домен недоступен; остаточные значения затёрты

            byte[] afterFirstRead = File.ReadAllBytes(path);

            bool secondResult = await data.ReadConfigAsync();
            Assert.False(secondResult); // домен по-прежнему недоступен

            // Второй прогон файл не трогает: непустых открытых значений больше нет
            Assert.Equal(afterFirstRead, File.ReadAllBytes(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Пара БД зачищает остаточные открытые значения: при валидных
    /// sdbuser/sdbpass и непустых dbuser/dbpass защищённая ветка
    /// перезаписывает файл, затирая открытые значения. После У1 (шаг 6)
    /// поведение всех трёх пар — домена, БД и TLS — симметрично;
    /// тест сохранён как независимая фиксация пары БД.
    /// </summary>
    [Fact]
    public async Task ReadConfigAsync_SecureDbCredentials_PlainLeftovers_Wiped()
    {
        (KeyStore keyStore, CryptoEngine cryptoEngine, byte[] key) = CreateCrypto();

        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            string encryptedDbUser = cryptoEngine.Encrypt("svc-db", key);
            string encryptedDbPass = cryptoEngine.Encrypt("db-secret", key);
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

            Data data = new Data(keyStore, cryptoEngine, path);
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
        (KeyStore keyStore, CryptoEngine cryptoEngine, byte[] key) = CreateCrypto();

        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            string certPath = Path.Combine(directory, "cert.pfx");
            File.WriteAllBytes(certPath, "not-a-real-pfx"u8.ToArray());
            string encryptedCertPass = cryptoEngine.Encrypt("cert-secret", key);

            DataConfigTestHelpers.WriteUtf8NoBom(path,
                $"domainname={UnreachableDomain}",
                "certpath=" + certPath,
                "scertpass=" + encryptedCertPass,
                "certpass=LEFTOVER-SECRET",
                "scheme=https",
                "port=38080");

            Data data = new Data(keyStore, cryptoEngine, path);
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
